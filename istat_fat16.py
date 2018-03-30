import struct
import fsstat_fat16


def as_unsigned(bs, endian='<'):
    unsigned_format = {1: 'B', 2: 'H', 4: 'L', 8: 'Q'}
    if len(bs) <= 0 or len(bs) > 8:
        raise ValueError()
    fill = '\x00'
    while len(bs) not in unsigned_format:
        bs += fill
    result = struct.unpack(endian + unsigned_format[len(bs)], bs)[0]
    return result


def decode_fat_time(time_bytes, tenths=0, tz='EDT'):
    v = as_unsigned(time_bytes)
    second = int(int(0x1F & v) * 2)
    if tenths > 100:
        second += 1
    minute = (0x7E0 & v) >> 5
    hour = (0xF800 & v) >> 11
    return '{:02}:{:02}:{:02} ({})'.format(hour, minute, second, tz)


def decode_fat_day(date_bytes):
    v = as_unsigned(date_bytes)
    day = 0x1F & v
    month = (0x1E0 & v) >> 5
    year = ((0xFE00 & v) >> 9) + 1980
    return '{}-{:02}-{:02}'.format(year, month, day)


def get_root_area_end(b, root_area_start, bytes_per_sector):
    return root_area_start + (as_unsigned(b[17:19]) * 32 // bytes_per_sector) - 1


def istat_fat16(f, address, sector_size=512, offset=0):
    result = []
    f.seek(offset * sector_size)
    boot_sector = f.read(sector_size)
    fat_size = fsstat_fat16.get_fat_size(boot_sector)  # reuse old code
    sectors_before_start = fsstat_fat16.get_sectors_start(boot_sector)  # reuse old code
    fat_start = sectors_before_start + 1
    number_of_fats = fsstat_fat16.get_number_fats(boot_sector)
    reserved_area_size = fsstat_fat16.get_reserved_area_size(boot_sector)
    root_area_start = sectors_before_start - offset + reserved_area_size + number_of_fats * fat_size
    bytes_per_sector = fsstat_fat16.get_bytes_per_sector(boot_sector)
    root_area_end = get_root_area_end(boot_sector, root_area_start, bytes_per_sector)
    cluster_start = root_area_end + 1
    cluster_size = fsstat_fat16.get_cluster_size(boot_sector)
    f.seek(offset * sector_size + ((root_area_start * sector_size) + (address - 3) * 32))
    directory_entry = f.read(32)

    result.append('Directory Entry: ' + str(address))

    if directory_entry[0] == 0xe5:
        result.append('Not Allocated')
    if directory_entry[0] == 0x00:
        result.append('Not Allocated')
    else:
        result.append('Allocated')

    attribute = directory_entry[11]
    file_attribute = "File Attributes: "
    if attribute & 0x0f == 0x0f:
        file_attribute += 'Long File Name'
    else:
        if attribute & 0x10:
            file_attribute += "Directory"
        elif attribute & 0x08:
            file_attribute += "Volume Label"
        else:
            file_attribute += "File"
        if attribute & 0x01:
            file_attribute += ", Read Only"
        if attribute & 0x02:
            file_attribute += ", Hidden"
        if attribute & 0x04:
            file_attribute += ", System"
        if attribute & 0x20:
            file_attribute += ", Archive"
    result.append(file_attribute)

    file_size = as_unsigned(directory_entry[28:32])
    f.seek(fat_start * sector_size)
    fat = f.read(fat_size * sector_size)
    fat = fat[4:]
    count = 0
    sector_count = file_size // sector_size
    cluster_number = fsstat_fat16.get_cluster_to_sector(as_unsigned(directory_entry[26:28]), cluster_size)
    cluster_offset = as_unsigned(fat[cluster_number:cluster_number + 2])
    cluster_line = []
    cluster_result = []
    flag = False

    while cluster_number < len(fat) and sector_count > 0:
        flag = True
        if len(cluster_line) == 8:
            cluster_result.append(" ".join(cluster_line))
            cluster_line = []
        for c in range(cluster_size):
            cluster_line.append(str(cluster_start + cluster_number + c))
        if 0xffff > cluster_offset > 0:
            cluster_number = fsstat_fat16.get_cluster_to_sector(cluster_offset, cluster_size)
        elif cluster_offset == 0xffff:
            flag = True
            break
        else:
            cluster_number += 2
        cluster_offset = as_unsigned(fat[cluster_number:cluster_number + 2])
        sector_count -= 2
        count += 2
    if len(cluster_line) == 8:
        cluster_result.append(" ".join(cluster_line))
        cluster_line = []

    if file_size == 0:
        for c in range(cluster_size):
            cluster_line.append(str(cluster_start + cluster_number + c))
            count += 1
    elif not flag or directory_entry[0] == 0xe5:
        rem_size = file_size % (sector_size * cluster_size)
        num_zeroes = rem_size // sector_size + 1
        for c in range(cluster_size - num_zeroes):
            cluster_line.append(str(cluster_start + cluster_number + c))
            count += 1
        for c in range(num_zeroes):
            cluster_line.append("0")
            count += 1
    if file_size == 0:
        result.append('Size: ' + str(count * sector_size))
    else:
        result.append('Size: ' + str(file_size))

    file_ext = "".join(i for i in directory_entry[8:12].decode('ascii') if 48 < ord(i) < 127)
    lowercase_byte = directory_entry[12]
    if directory_entry[0] == 0xe5:
        filename = '_'
    else:
        filename = directory_entry[0:1].decode('ascii').strip()
    filename += directory_entry[1:8].decode('ascii').strip()
    if lowercase_byte & 0x08:
        filename = filename.lower()
    if file_ext:
        if lowercase_byte & 0x10:
            filename += "." + file_ext.lower()
        else:
            filename += "." + file_ext
    result.append('Name: ' + filename)

    result.append('')
    result.append('Directory Entry Times:')
    result.append('Written:\t' + decode_fat_day(directory_entry[24:26]) + " " + decode_fat_time(directory_entry[22:24]))
    result.append('Accessed:\t' + decode_fat_day(directory_entry[18:20]) + " " + decode_fat_time(bytes.fromhex('0000')))
    result.append(
        'Created:\t' + decode_fat_day(directory_entry[16:18]) + " " + decode_fat_time(directory_entry[14:16], directory_entry[13]))
    result.append('')

    result.append('Sectors:')
    for c in cluster_result:
        result.append(c)
    if len(cluster_line) > 0:
        result.append(" ".join(cluster_line))
    return result


if __name__ == '__main__':
    with open('adams.dd', 'rb') as f:
        lines = istat_fat16(f, 549)
        for line in lines:
            print(line)
