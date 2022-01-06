#!/usr/bin/python3

import re
import sys
import argparse
from pathlib import Path
from collections import namedtuple
from struct import pack, unpack, calcsize

SPARSE_HEADER_MAGIC = 0xED26FF3A
SPARSE_HEADER_SIZE = 28
SPARSE_CHUNK_HEADER_SIZE = 12

LP_PARTITION_RESERVED_BYTES = 4096
LP_METADATA_GEOMETRY_MAGIC = 0x616c4467
LP_METADATA_GEOMETRY_SIZE = 4096
LP_METADATA_HEADER_MAGIC = 0x414C5030
LP_SECTOR_SIZE = 512


class SparseHeader(object):
    def __init__(self, buffer):
        fmt = '<I4H4I'
        (
            self.magic,             # 0xed26ff3a
            self.major_version,     # (0x1) - reject images with higher major versions
            self.minor_versionm,    # (0x0) - allow images with higer minor versions
            self.file_hdr_sz,       # 28 bytes for first revision of the file format
            self.chunk_hdr_sz,      # 12 bytes for first revision of the file format
            self.blk_sz,            # block size in bytes, must be a multiple of 4 (4096)
            self.total_blks,        # total blocks in the non-sparse output image
            self.total_chunks,      # total chunks in the sparse input image
            self.image_checksum     # CRC32 checksum of the original data, counting "don't care"
        ) = unpack(fmt, buffer[0:calcsize(fmt)])


class SparseChunkHeader(object):
    """
        Following a Raw or Fill or CRC32 chunk is data.
        For a Raw chunk, it's the data in chunk_sz * blk_sz.
        For a Fill chunk, it's 4 bytes of the fill data.
        For a CRC32 chunk, it's 4 bytes of CRC32
     """
    def __init__(self, buffer):
        fmt = '<2H2I'
        (
            self.chunk_type,        # 0xCAC1 -> raw; 0xCAC2 -> fill; 0xCAC3 -> don't care */
            self.reserved1,
            self.chunk_sz,          # in blocks in output image * /
            self.total_sz,          # in bytes of chunk input file including chunk header and data * /
        ) = unpack(fmt, buffer[0:calcsize(fmt)])


class LpMetadataGeometry(object):
    """
        Offset 0: Magic signature
        Offset 4: Size of the LpMetadataGeometry
        Offset 8: SHA256 checksum
        Offset 40: Maximum amount of space a single copy of the metadata can use
        Offset 44: Number of copies of the metadata to keep
        Offset 48: Logical block size
    """
    def __init__(self, buffer):
        fmt = '<2I32s3I'
        (
            self.magic,
            self.struct_size,
            self.checksum,
            self.metadata_max_size,
            self.metadata_slot_count,
            self.logical_block_size

        ) = unpack(fmt, buffer[0:calcsize(fmt)])


class LpMetadataHeader(object):
    """
        +-----------------------------------------+
        | Header data - fixed size                |
        +-----------------------------------------+
        | Partition table - variable size         |
        +-----------------------------------------+
        | Partition table extents - variable size |
        +-----------------------------------------+
    """
    def __init__(self, buffer):
        fmt = '<I2hI32sI32s'
        (
            self.magic,
            self.major_version,
            self.minor_version,
            self.header_size,
            self.header_checksum,
            self.tables_size,
            self.tables_checksum

        ) = unpack(fmt, buffer[0:calcsize(fmt)])
        self.partitions = None
        self.extents = None
        self.groups = None
        self.block_devices = None


class LpMetadataTableDescriptor(object):
    def __init__(self, buffer):
        fmt = '<3I'
        (
            self.offset,
            self.num_entries,
            self.entry_size

        ) = unpack(fmt, buffer[:calcsize(fmt)])


class LpMetadataPartition(object):
    def __init__(self, buffer):
        fmt = '<36s4I'
        (
            self.name,
            self.attributes,
            self.first_extent_index,
            self.num_extents,
            self.group_index

        ) = unpack(fmt, buffer[0:calcsize(fmt)])


class LpMetadataExtent(object):
    def __init__(self, buffer):
        fmt = '<QIQI'
        (
            self.num_sectors,
            self.target_type,
            self.target_data,
            self.target_source

        ) = unpack(fmt, buffer[0:calcsize(fmt)])


class LpMetadataPartitionGroup(object):
    def __init__(self, buffer):
        fmt = '<36sIQ'
        (
            self.name,
            self.flags,
            self.maximum_size
        ) = unpack(fmt, buffer[0:calcsize(fmt)])


class LpMetadataBlockDevice(object):
    def __init__(self, buffer):
        fmt = '<Q2IQ36sI'
        (
            self.first_logical_sector,
            self.alignment,
            self.alignment_offset,
            self.size,
            self.partition_name,
            self.flags
        ) = unpack(fmt, buffer[0:calcsize(fmt)])


class Metadata(object):
    def __init__(self):
        self.geometry = None
        self.partitions = []
        self.extents = []
        self.groups = []
        self.block_devices = []


class LpUnpackError(Exception):
    """Raised any error unpacking"""
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


class SparseImage(object):
    def __init__(self, fd):
        self._fd = fd
        self.header = None

    def check(self):
        self._fd.seek(0)
        self.header = SparseHeader(self._fd.read(SPARSE_HEADER_SIZE))
        return False if self.header.magic != SPARSE_HEADER_MAGIC else True

    def unsparse(self):
        if not self.header:
            self._fd.seek(0)
            self.header = SparseHeader(self._fd.read(SPARSE_HEADER_SIZE))
        chunks = self.header.total_chunks
        self._fd.seek(self.header.file_hdr_sz - SPARSE_HEADER_SIZE, 1)
        unsparse_file_dir = Path(self._fd.name).parent
        unsparse_file = Path(unsparse_file_dir / "{}.unsparse.img".format(Path(self._fd.name).stem))
        with open(str(unsparse_file), 'wb') as out:
            sector_base = 82528
            output_len = 0
            while chunks > 0:
                chunk_header = SparseChunkHeader(self._fd.read(SPARSE_CHUNK_HEADER_SIZE))
                sector_size = (chunk_header.chunk_sz * self.header.blk_sz) >> 9
                chunk_data_size = chunk_header.total_sz - self.header.chunk_hdr_sz
                if chunk_header.chunk_type == 0xCAC1:
                    if self.header.chunk_hdr_sz > SPARSE_CHUNK_HEADER_SIZE:
                        self._fd.seek(self.header.chunk_hdr_sz - SPARSE_CHUNK_HEADER_SIZE, 1)
                    data = self._fd.read(chunk_data_size)
                    len_data = len(data)
                    if len_data == (sector_size << 9):
                        out.write(data)
                        output_len += len_data
                        sector_base += sector_size
                else:
                    if chunk_header.chunk_type == 0xCAC2:
                        if self.header.chunk_hdr_sz > SPARSE_CHUNK_HEADER_SIZE:
                            self._fd.seek(self.header.chunk_hdr_sz - SPARSE_CHUNK_HEADER_SIZE, 1)
                        data = self._fd.read(chunk_data_size)
                        len_data = sector_size << 9
                        out.write(pack("B", 0) * len_data)
                        output_len += len(data)
                        sector_base += sector_size
                    else:
                        if chunk_header.chunk_type == 0xCAC3:
                            if self.header.chunk_hdr_sz > SPARSE_CHUNK_HEADER_SIZE:
                                self._fd.seek(self.header.chunk_hdr_sz - SPARSE_CHUNK_HEADER_SIZE, 1)
                            data = self._fd.read(chunk_data_size)
                            len_data = sector_size << 9
                            out.write(pack("B", 0) * len_data)
                            output_len += len(data)
                            sector_base += sector_size
                        else:
                            len_data = sector_size << 9
                            out.write(pack("B", 0) * len_data)
                            sector_base += sector_size
                chunks -= 1
        return unsparse_file


class LpUnpack(object):
    def __init__(self, **kwargs):
        self.partition_name = kwargs.get('NAME')
        self.slot_num = None
        # self.slot_num = int(kwargs.get('NUM')) if kwargs.get('NUM') else 0
        self.in_file_fd = open(kwargs.get('SUPER_IMAGE'), 'rb')
        self.out_dir = kwargs.get('OUTPUT_DIR')

    def _CheckOutDirExists(self):
        out_dir = Path(self.out_dir)
        if not out_dir.exists():
            out_dir.mkdir(parents=True, exist_ok=True)
        self.out_dir = out_dir

    def _ReadChunk(self, block_size):
        while True:
            data = self.in_file_fd.read(block_size)
            if not data:
                break
            yield data

    def ReadPrimaryGeometry(self):
        lpMetadataGeometry = LpMetadataGeometry(self.in_file_fd.read(LP_METADATA_GEOMETRY_SIZE))
        if lpMetadataGeometry is not None:
            return lpMetadataGeometry
        else:
            return self.ReadBackupGeometry()

    def ReadBackupGeometry(self):
        return LpMetadataGeometry(self.in_file_fd.read(LP_METADATA_GEOMETRY_SIZE))

    def GetPrimaryMetadataOffset(self, geometry, slot_number=0):
        return LP_PARTITION_RESERVED_BYTES + (LP_METADATA_GEOMETRY_SIZE * 2) + geometry.metadata_max_size * slot_number

    def GetBackupMetadataOffset(self, geometry, slot_number=0):
        start = LP_PARTITION_RESERVED_BYTES + (LP_METADATA_GEOMETRY_SIZE * 2) + \
                geometry.metadata_max_size * geometry.metadata_slot_count
        return start + geometry.metadata_max_size * slot_number

    def ParseHeaderMetadata(self, offsets):
        header = None
        for index, offset in enumerate(offsets):
            self.in_file_fd.seek(offset, 0)
            header = LpMetadataHeader(self.in_file_fd.read(80))
            header.partitions = LpMetadataTableDescriptor(self.in_file_fd.read(12))
            header.extents = LpMetadataTableDescriptor(self.in_file_fd.read(12))
            header.groups = LpMetadataTableDescriptor(self.in_file_fd.read(12))
            header.block_devices = LpMetadataTableDescriptor(self.in_file_fd.read(12))

            if header.magic != LP_METADATA_HEADER_MAGIC:
                if index + 1 > len(offsets):
                    raise LpUnpackError('Logical partition metadata has invalid magic value.')
                else:
                    print('Read Backup header by offset 0x{:x}'.format(offsets[index + 1]))
                    continue

            self.in_file_fd.seek(offset + header.header_size, 0)

        return header

    def ReadMetadata(self):
        metadata = Metadata()
        self.in_file_fd.seek(LP_PARTITION_RESERVED_BYTES, 0)
        metadata.geometry = self.ReadPrimaryGeometry()

        if metadata.geometry.magic != LP_METADATA_GEOMETRY_MAGIC:
            raise LpUnpackError('Logical partition metadata has invalid geometry magic signature.')

        if metadata.geometry.metadata_slot_count == 0:
            raise LpUnpackError('Logical partition metadata has invalid slot count.')

        if metadata.geometry.metadata_max_size % LP_SECTOR_SIZE != 0:
            raise LpUnpackError('Metadata max size is not sector-aligned.')

        offsets = [self.GetPrimaryMetadataOffset(metadata.geometry, slot_number=0), #self.slot_num
                   self.GetBackupMetadataOffset(metadata.geometry, slot_number=0)] #self.slot_num

        metadata.header = self.ParseHeaderMetadata(offsets)

        for index in range(0, metadata.header.partitions.num_entries):
            partition = LpMetadataPartition(self.in_file_fd.read(metadata.header.partitions.entry_size))
            partition.name = str(partition.name, 'utf-8').strip('\x00')
            metadata.partitions.append(partition)

        for index in range(0, metadata.header.extents.num_entries):
            metadata.extents.append(LpMetadataExtent(self.in_file_fd.read(metadata.header.extents.entry_size)))

        for index in range(0, metadata.header.groups.num_entries):
            group = LpMetadataPartitionGroup(self.in_file_fd.read(metadata.header.groups.entry_size))
            group.name = str(group.name, 'utf-8').strip('\x00')
            metadata.groups.append(group)

        for index in range(0, metadata.header.block_devices.num_entries):
            block_device = LpMetadataBlockDevice(self.in_file_fd.read(metadata.header.block_devices.entry_size))
            block_device.partition_name = str(block_device.partition_name, 'utf-8').strip('\x00')
            metadata.block_devices.append(block_device)

        try:
            super_device = metadata.block_devices[0]
            metadata_region = LP_PARTITION_RESERVED_BYTES + (LP_METADATA_GEOMETRY_SIZE +
                                                             metadata.geometry.metadata_max_size *
                                                             metadata.geometry.metadata_slot_count) * 2
            if metadata_region > super_device.first_logical_sector * LP_SECTOR_SIZE:
                raise LpUnpackError('Logical partition metadata overlaps with logical partition contents.')
        except IndexError:
            raise LpUnpackError('Metadata does not specify a super device.')

        return metadata

    def ExtractPartition(self, meta):
        self._CheckOutDirExists()
        print('Extracting partition [{}] ....'.format(meta.name), end='', flush=True)
        out_file = Path(self.out_dir / "{name}.img".format(name=meta.name))
        size = meta.size
        self.in_file_fd.seek(meta.offset)
        with open(str(out_file), 'wb') as out:
            for block in self._ReadChunk(meta.geometry.logical_block_size):
                if size == 0:
                    break
                out.write(block)
                size -= meta.geometry.logical_block_size
        print(' [ok]')

    def Extract(self, partition, metadata):
        offset = 0
        size = 0

        unpack = namedtuple('Unpack', 'name offset size geometry')

        if partition.num_extents != 0:
            extent = metadata.extents[partition.first_extent_index]
            offset = extent.target_data * LP_SECTOR_SIZE
            size = extent.num_sectors * LP_SECTOR_SIZE

        self.ExtractPartition(unpack(partition.name, offset, size, metadata.geometry))

    def unpack(self):
        try:
            if SparseImage(self.in_file_fd).check():
                print('Sparse image detected.')
                print('Process conversion to non sparse image ....', end='', flush=True)
                unsparse_file = SparseImage(self.in_file_fd).unsparse()
                self.in_file_fd.close()
                self.in_file_fd = open(str(unsparse_file), 'rb')
                print('[ok]')

            self.in_file_fd.seek(0)
            metadata = self.ReadMetadata()

            if self.partition_name:
                filter_partition = []
                filter_extents = []
                for index, partition in enumerate(metadata.partitions):
                    if partition.name in self.partition_name:
                        filter_partition.append(partition)
                        filter_extents.append(metadata.extents[index])
                if not filter_partition:
                    raise LpUnpackError('Could not find partition: {}'.format(self.partition_name))
                metadata.partitions = filter_partition
                metadata.extents = filter_extents

            if self.slot_num:
                if self.slot_num > metadata.geometry.metadata_slot_count:
                    raise LpUnpackError('Invalid metadata slot number: {}'.format(self.slot_num))

            for partition in metadata.partitions:
                self.Extract(partition, metadata)

        except LpUnpackError as e:
            print(e.message)
            sys.exit(1)
        finally:
            self.in_file_fd.close()


def create_parser():
    parser = argparse.ArgumentParser(description='{} - command-line tool for extracting partition images from super'
                                     .format(Path(sys.argv[0]).name))
    parser.add_argument(
        '-p',
        '--partition',
        dest='NAME',
        type=lambda x: re.split("\W+", x),
        help='Extract the named partition. This can be specified multiple times or through the delimiter [","  ":"]'
    )
    parser.add_argument(
        '-S',
        '--slot',
        dest='NUM',
        type=int,
        help=' !!! No implementation yet !!! Slot number (default is 0).'
    )
    parser.add_argument('SUPER_IMAGE')
    parser.add_argument(
        'OUTPUT_DIR',
        type=str,
    )
    return parser


def help(parser):
    parser.print_help()
    sys.exit(2)


if __name__ == '__main__':
    parser = create_parser()
    namespace = parser.parse_args()
    if len(sys.argv) >= 2:
        if not Path(namespace.SUPER_IMAGE).exists():
            help(parser)
        LpUnpack(**vars(namespace)).unpack()
    else:
        parser.print_usage()
        sys.exit(1)
