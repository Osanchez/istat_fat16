import struct


# Some of the helper functions including 'as_le_unsigned' and 'get_cluster_numbers' were gathered from course website
# http://people.cs.umass.edu/~liberato/courses/2018-spring-compsci365+590f/lecture-notes/12-demonstration-parsing-fat/


def as_le_unsigned(b):
    table = {1: 'B', 2: 'H', 4: 'L', 8: 'Q'}
    return struct.unpack('<' + table[len(b)], b)[0]


def get_cluster_numbers(first_cluster, fat_bytes, cluster_size):
    result = [first_cluster]
    offset = 2 * first_cluster
    next_cluster = as_le_unsigned(fat_bytes[offset:offset + 2])
    while next_cluster < as_le_unsigned(b'\xf8\xff'):
        result.append(next_cluster)
        offset = 2 * next_cluster
        next_cluster = as_le_unsigned(fat_bytes[offset:offset + 2])
    return result


def get_cluster_to_sector(cluster, cluster_size):
    return (cluster - 2) * cluster_size


def get_oem_name(b):
    return b[3:11].decode('ascii').strip()


def get_volume_id(b):
    return hex(as_le_unsigned(b[39:43]))


def get_volume_label(b):
    return b[43:54].decode('ascii').strip()


def get_filesystem_type(b):
    return b[54:62].decode('ascii').strip()


def get_sectors_start(b):
    return as_le_unsigned(b[28:32])


def get_sector_count(b):
    return max(as_le_unsigned(b[19:21]), as_le_unsigned(b[32:36])) - 1


def get_reserved_area_size(b):
    return as_le_unsigned(b[14:16])


def get_fat_size(b):
    return as_le_unsigned(b[22:24])


def get_fat_start(b, offset):
    return get_sectors_start(b) - offset + 1


def get_number_fats(b):
    return as_le_unsigned(b[16:17])


def get_bytes_per_sector(b):
    return as_le_unsigned(b[11:13])


def get_cluster_size(b):
    return as_le_unsigned(b[13:14])


def fsstat_fat16(fat16_file, sector_size=512, offset=0):

    result = ['FILE SYSTEM INFORMATION',
              '--------------------------------------------',
              'File System Type: FAT16',
              '']

    fat16_file.seek(offset * sector_size)
    boot_sector = fat16_file.read(sector_size)

    fat16_file.seek(offset * sector_size)
    boot_sector = fat16_file.read(sector_size)
    result.append('OEM Name: ' + get_oem_name(boot_sector))
    result.append('Volume ID: ' + get_volume_id(boot_sector))
    result.append('Volume Label (Boot Sector): ' + get_volume_label(boot_sector))
    result.append('File System Type Label: ' + get_filesystem_type(boot_sector))
    result.append('')
    result.append('Sectors before file system: ' + str(get_sectors_start(boot_sector)))
    result.append('')
    result.append('File System Layout (in sectors)')
    result.append(
        'Total Range: ' + str(get_sectors_start(boot_sector) - offset) + ' - ' + str(get_sector_count(boot_sector)))
    result.append('* Reserved: ' + str(get_sectors_start(boot_sector) - offset) + ' - '
                  + str(get_sectors_start(boot_sector) - offset + get_reserved_area_size(boot_sector) - 1))
    result.append('** Boot Sector: ' + str(get_sectors_start(boot_sector) - offset))
    fat_start = get_fat_start(boot_sector, offset)
    fat_size = get_fat_size(boot_sector)
    sector_start = get_sectors_start(boot_sector)
    reserved_area_size = get_reserved_area_size(boot_sector)
    number_fats = get_number_fats(boot_sector)
    sector_count = get_sector_count(boot_sector)
    for num_fats in range(get_number_fats(boot_sector)):
        result.append('* FAT ' + str(num_fats) + ': ' + str(fat_start) + ' - ' + str(fat_start + fat_size - 1))
        fat_start = (num_fats + 1) * fat_size + 1
    fat_start = sector_start + 1
    data_area_start = sector_start - offset + reserved_area_size + number_fats * fat_size
    result.append('* Data Area: ' + str(data_area_start) + ' - ' + str(sector_count))
    root_area_end = data_area_start + (as_le_unsigned(boot_sector[17:19]) * 32 // get_bytes_per_sector(boot_sector)) - 1
    result.append('** Root Directory: ' + str(data_area_start) + ' - ' + str(root_area_end))
    cluster_size = get_cluster_size(boot_sector)
    num_clusters = (sector_count - root_area_end) // cluster_size
    cluster_area_end = root_area_end + cluster_size * num_clusters
    result.append('** Cluster Area: ' + str(root_area_end + 1) + ' - ' + str(cluster_area_end))
    if sector_count - cluster_area_end != 0:
        result.append('** Non-clustered: ' + str(cluster_area_end + 1) + ' - ' + str(sector_count))
    result.append('')
    result.append('CONTENT INFORMATION')
    result.append('--------------------------------------------')
    result.append('Sector Size: ' + str(sector_size))
    result.append('Cluster Size: ' + str(cluster_size * sector_size))
    result.append('Total Cluster Range: 2 - ' + str(num_clusters + 1))
    result.append('')
    result.append('FAT CONTENTS (in sectors)')
    result.append('--------------------------------------------')
    fat16_file.seek(fat_start * sector_size)
    fat = fat16_file.read(fat_size * sector_size)
    cluster_start = root_area_end + 1
    file_start = cluster_start
    flag_check = False
    fat = fat[4:]
    for x in range(0, len(fat), 2):
        cluster_number = x
        cluster_offset = as_le_unsigned(fat[x: x + 2])
        if 0xffff > cluster_offset > 0:
            if not flag_check:
                file_start = cluster_start + cluster_number
                flag_check = True
            else:
                cluster_sector = get_cluster_to_sector(cluster_offset, cluster_size)
                if cluster_sector - cluster_number != 2:
                    file_end = cluster_start + cluster_number + 1
                    result.append(
                        str(file_start) + '-' + str(file_end) + ' (' + str(file_end - file_start + 1) + ') -> ' + str(
                            cluster_start + cluster_sector))
                    flag_check = False
        elif cluster_offset == 0xffff:
            file_end = cluster_start + cluster_number + 1
            if not flag_check:
                file_start = cluster_start + cluster_number
            result.append(str(file_start) + '-' + str(file_end) + ' (' + str(file_end - file_start + 1) + ') -> EOF')
            flag_check = False
        else:
            flag_check = False

    return result


if __name__ == "__main__":
    with open('adams.dd', 'rb') as f:
        result = fsstat_fat16(f, 1024)
        for line in result:
            print(line)