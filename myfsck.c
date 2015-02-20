#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<fcntl.h>
#include<inttypes.h>
#include<stdbool.h>
#include "ext2_fs.h"

static int device;
const unsigned int sector_size_bytes = 512;
typedef struct {
    unsigned char part_type;
    uint32_t partition_start;
    uint32_t partition_length;
} p_metadata;


typedef struct {
    uint32_t bg_block_bitmap;
    uint32_t bg_inode_bitmap;
    uint32_t bg_inode_table;
    uint16_t bg_free_blocks_count;
    uint16_t bg_free_inodes_count;
} gd;

typedef struct {
    uint16_t i_mode;
    uint32_t i_size;
    uint16_t i_links_count;
    uint32_t i_blocks;
    uint32_t i_flags;
    uint32_t  i_block[15];
} inode;

void get_partition_details(int part_number, p_metadata *data);
void read_sectors (int64_t start_sector, unsigned int num_sectors, void *into);
void read_superblock_info(int part_number, struct ext2_super_block *superblock);
void read_gd_info(int part_number, struct ext2_group_desc *gd_info);
unsigned char get_partition_type (unsigned char *sector, int part_num);
void read_inode_info(uint32_t i_block_start, uint32_t inode_num, struct ext2_inode *i_info
        ,struct ext2_group_desc *gd_info, struct ext2_super_block *superblock, uint32_t partition_number);
bool inode_allocated(uint32_t inode_num, struct ext2_group_desc *gd_info, uint32_t partition_number);

int block_size;
int sectors_per_block;

int main (int argc, char **argv){
    int part_number;
    char *image_path;
    int c;
    while ((c = getopt (argc, argv, "p:i:")) != -1) {
        switch (c)
            {
                case 'p':
                    part_number = atoi(optarg);
                    if(part_number <= 0) {
                        fprintf(stderr, "Option 'p' requires a positive integer argument\n. Will exit now...");
                        exit(-1);
                    }
                    break;
                case 'i':
                    image_path = optarg;
                    strncpy(image_path, optarg, 100);
                    break;
                case '?':
                    if (optopt == 'p' || optopt == 'i')
                        fprintf(stderr, "Argument not given for option %c\n", optopt);
                    else if (isprint(optopt))
                        fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                    else
                        fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                    exit(-1);
                    break;
                default:
                    break;
            }
    }


    if ((device = open(image_path, O_RDWR)) == -1) {
        perror("Could not open device file");
        exit(-1);
    } 
    p_metadata part_detail;
    get_partition_details(part_number, &part_detail);
    if (part_detail.part_type != 0xFF) {
        printf("0x%02X %d %d\n", part_detail.part_type, part_detail.partition_start, 
                part_detail.partition_length);
    }
    else 
        printf("-1\n");

    struct ext2_super_block super;
    read_superblock_info(part_number, &super);
    printf("Magic number is 0x%02x\n", super.s_magic);
    block_size = 1024 << super.s_log_block_size;
    sectors_per_block = block_size / sector_size_bytes;

    struct ext2_group_desc gd_info;
    read_gd_info(part_number, &gd_info);
    uint32_t inode_table_start = gd_info.bg_inode_table;

    struct ext2_inode i_info;
    read_inode_info(inode_table_start, 2, &i_info, 
            &gd_info, &super, part_detail.partition_start);
    printf("Inode mode is: %d\n", i_info.i_mode);

    if (inode_allocated(2, &gd_info, part_detail.partition_start))
        printf("Inode %d is allocated!\n", 2);
    else
        printf("Inode %d is not allocated!\n", 2);

    //read_directory_entries
}



/* read_sectors: read a specified number of sectors into a buffer.
 *
 * inputs:
 *   int64 start_sector: the starting sector number to read.
 *                       sector numbering starts with 0.
 *   int numsectors: the number of sectors to read.  must be >= 1.
 *   int device [GLOBAL]: the disk from which to read.
 *
 * outputs:
 *   void *into: the requested number of sectors are copied into here.
 *
 * modifies:
 *   void *into
 */
void read_sectors (int64_t start_sector, unsigned int num_sectors, void *into)
{
    ssize_t ret;
    int64_t lret;
    int64_t sector_offset;
    ssize_t bytes_to_read;

    sector_offset = start_sector * sector_size_bytes;

    if ((lret = lseek64(device, sector_offset, SEEK_SET)) != sector_offset) {
        fprintf(stderr, "Seek to position %"PRId64" failed: "
                "returned %"PRId64"\n", sector_offset, lret);
        exit(-1);
    }

    bytes_to_read = sector_size_bytes * num_sectors;

    if ((ret = read(device, into, bytes_to_read)) != bytes_to_read) {
        fprintf(stderr, "Read sector %"PRId64" length %d failed: "
                "returned %"PRId64"\n", start_sector, num_sectors, ret);
        exit(-1);
    }
}


void get_partition_details(int part_number, p_metadata *data){
    if (part_number < 0) {
        data->part_type = -1;
        return ;
    }
    int curr_part_number = 0;
    int curr_sector = 0; 
    unsigned char buf[sector_size_bytes];
    int ebr_start_lba = 0;
    int prev_ebr_lba = 0;
    int prev_sector = 0;
    int part_start;
    int part_length;
    unsigned char part_type;

    while (curr_part_number <= part_number) {
        read_sectors(curr_sector, 1, buf);
        prev_sector = curr_sector;
        int i;
        for (i = 0; i < 4; i++){
            part_type = get_partition_type(buf, i);

            //Check if partition 2 is not EBR, then break
            if (curr_sector != 0 && i == 1 && part_type != 0x05)
                break;
            if (!(part_type == 0x05 && curr_sector != 0)){  //Increment counter if not EBR in sector 0
                curr_part_number++;
                if (curr_part_number > part_number) {
                    data->part_type = -1;
                    return;
                }
            }
            if (curr_part_number == part_number) {
                part_start = (prev_sector == 0 ? 0 : curr_sector) + get_partition_start(buf, i);
                part_length = get_partition_length(buf, i);
                data->part_type = part_type;
                data->partition_start = part_start;
                data->partition_length = part_length;
                return;
            }
            if (part_type == 0x05 && curr_sector == 0) {
                ebr_start_lba = get_partition_start(buf, i);
                prev_ebr_lba = ebr_start_lba;
                prev_sector = curr_sector;
                curr_sector = ebr_start_lba;
            }
            else if (part_type == 0x05 && curr_sector != 0) {
                prev_ebr_lba = get_partition_start(buf, i);
                prev_sector = curr_sector;
                curr_sector = ebr_start_lba + prev_ebr_lba;
                break;
            }
        }
        if (curr_sector == prev_sector)
            break;
    } 
    if (curr_part_number < part_number) {
        data->part_type = -1;
        return;
    }
}

//Assume least significant byte in buf[3]
int convert_bytes_to_uint32 (unsigned char *buf) {
    return buf[3] + (buf[2] << 8) + (buf[1] << 16) + (buf[0] << 24);
}

//Assume least significant byte in buf[1]
int convert_bytes_to_uint16 (unsigned char *buf) {
    return buf[1] + (buf[0] << 8);
}

//Assume least significant byte in buf[1]
unsigned char convert_bytes_to_byte (unsigned char *buf) {
    return buf[0];
}

int read_bytes (unsigned char *sector, int offset, int num_bytes) {
    unsigned char buf[4];
    int i;
    for (i = num_bytes - 1; i >= 0; i--){
        buf[i] = sector[offset++];
    }
    if (num_bytes == 2)
        return convert_bytes_to_uint16(buf);
    else if (num_bytes == 4)
        return convert_bytes_to_uint32(buf);
    else
        return convert_bytes_to_byte(buf);
}

int get_partition_length (unsigned char *sector, int part_num) {
    int byte_offset = 446 + (part_num) * 16 + 12;
    return read_bytes(sector, byte_offset, 4);
}

int get_partition_start (unsigned char *sector, int part_num) {
    int byte_offset = 446 + (part_num) * 16 + 8;
    return read_bytes(sector, byte_offset, 4);
}

int get_magic_number (unsigned char *sector) {
    unsigned char buf[2];
    int byte_offset = 56;
    return read_bytes(sector, byte_offset, 2);
}

unsigned char get_partition_type (unsigned char *sector, int part_num) {
    return sector[446 + (part_num) * 16 + 4];
}

void read_superblock_info(int part_number, struct ext2_super_block *superblock) {
    unsigned char buf[sector_size_bytes];
    p_metadata part_detail;
    get_partition_details(part_number, &part_detail);
    read_sectors(part_detail.partition_start + 2, 1, buf);
    superblock->s_inodes_count = read_bytes(buf, 0, 4);
    superblock->s_blocks_count = read_bytes(buf, 4, 4);
    superblock->s_free_blocks_count = read_bytes(buf, 12, 4);
    superblock->s_free_inodes_count = read_bytes(buf, 16, 4);
    superblock->s_log_block_size = read_bytes(buf, 24, 4);
    superblock->s_blocks_per_group = read_bytes(buf, 32, 4);
    superblock->s_inodes_per_group = read_bytes(buf, 40, 4);
    superblock->s_magic = read_bytes(buf, 56, 4);
    superblock->s_inode_size = read_bytes(buf, 88, 2);
    return;
}

void read_gd_info(int part_number, struct ext2_group_desc *gd_info) {
    unsigned char buf[sector_size_bytes * sectors_per_block];
    p_metadata part_detail;
    get_partition_details(part_number, &part_detail);
    read_sectors(part_detail.partition_start + (sectors_per_block * 2), sectors_per_block, buf);
    gd_info->bg_block_bitmap = read_bytes(buf, 0, 4);
    gd_info->bg_inode_bitmap = read_bytes(buf, 4, 4);
    gd_info->bg_inode_table = read_bytes(buf, 8, 4);
    gd_info->bg_free_blocks_count = read_bytes(buf, 12, 2);
    gd_info->bg_free_inodes_count = read_bytes(buf, 14, 2);
    return;
}

uint32_t get_inode_sector_offset(uint32_t inode_size, uint32_t inode_num) {
    return inode_num/(sector_size_bytes/inode_size);
}

void read_inode_info(uint32_t i_block_start, uint32_t inode_num, struct ext2_inode *i_info, 
        struct ext2_group_desc *gd_info, struct ext2_super_block *superblock, uint32_t part_start) {
    unsigned char buf[sector_size_bytes];
    read_sectors(part_start + (i_block_start * sectors_per_block) + get_inode_sector_offset(superblock->s_inode_size, inode_num), 
            1, buf);
    uint32_t num_inodes_sector = sector_size_bytes / superblock->s_inode_size;
    uint32_t offset = ((inode_num % num_inodes_sector) - 1) * superblock->s_inode_size; 
    i_info->i_mode = read_bytes(buf, offset + 0, 2);
    i_info->i_size = read_bytes(buf, offset + 4, 4);
    
}

bool inode_allocated(uint32_t inode_num, struct ext2_group_desc *gd_info, uint32_t part_start) {
    unsigned char buf[sector_size_bytes];
   uint32_t bitmap_block = gd_info->bg_inode_bitmap; 
   int byte_offset = inode_num / 8;
   read_sectors(part_start + (bitmap_block * 2), 1, buf);
   unsigned char bitmap_byte = read_bytes(buf, byte_offset, 1);
   if (bitmap_byte & (1 << (inode_num % 8)))
       return true;
   else
       return false;
}

