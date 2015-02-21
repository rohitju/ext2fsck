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

typedef enum {DIRECTORY_DATA_BLOCK, FILE_DATA_BLOCK} db_type;

void get_partition_details(int part_number, p_metadata *data);
void read_sectors (int64_t start_sector, unsigned int num_sectors, void *into);
void read_superblock_info(int part_number, struct ext2_super_block *superblock);
void read_gd_info(int part_number, struct ext2_group_desc *gd_info);
unsigned char get_partition_type (unsigned char *sector, int part_num);
void read_inode_info(uint32_t inode_num, struct ext2_inode *i_info);
bool inode_allocated(uint32_t inode_num, struct ext2_group_desc *gd_info, uint32_t partition_number);
void read_data_block(uint32_t block_num, db_type type);
void read_group_descriptor_table();
void traverse_directories(int inode_num);
void fix_directory_pointers(int inode_num, int parent_inode_num);
void indirect_traversal(int curr_level, int max_indirection, int block_num, db_type type);
struct ext2_dir_entry_2* read_directory_block(int block_num, int *count);
void write_sectors (int64_t start_sector, unsigned int num_sectors, void *from);

int block_size;
int sectors_per_block;
uint32_t partition_start;
struct ext2_super_block super;
char *group_descriptor_table;

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
    partition_start = part_detail.partition_start;
    if (part_detail.part_type != 0xFF) {
        printf("0x%02X %d %d\n", part_detail.part_type, part_detail.partition_start, 
                part_detail.partition_length);
    }
    else 
        printf("-1\n");

    read_superblock_info(part_number, &super);
    //printf("Magic number is 0x%02x\n", super.s_magic);
    block_size = 1024 << super.s_log_block_size;
    sectors_per_block = block_size / sector_size_bytes;
    group_descriptor_table = (char*)malloc(sectors_per_block * sector_size_bytes);
    read_group_descriptor_table();


   /* struct ext2_inode i_info;
    read_inode_info(inode_table_start, 2, &i_info, 
            &gd_info, &super, part_detail.partition_start);
    printf("Inode mode is: %d\n", i_info.i_mode);*/

    /*if (inode_allocated(2, &gd_info, part_detail.partition_start))
        printf("Inode %d is allocated!\n", 2);
    else
        printf("Inode %d is not allocated!\n", 2);*/

    //Look for lions in /
    /*int i;
    for(i = 0; i < 12; i++){
        if(i_info.i_block[i] == 0)
            continue;
        //printf("Data block %d is %d\n", i, i_info.i_block[i]);
        //read_directory_data_block(i_info.block[i]);
        read_directory_data_block(i_info.i_block[i]);
    }*/
    //traverse_directories(2);

    fix_directory_pointers(2, 2);
}

void read_group_descriptor_table(){
    read_sectors(partition_start + (sectors_per_block * 2), sectors_per_block, group_descriptor_table);
}

void indirect_traversal(int curr_level, int max_indirection, int block_num, db_type type){
    int offset = 0;
    unsigned char buf[sector_size_bytes * sectors_per_block];
    read_sectors(partition_start + (sectors_per_block * block_num), sectors_per_block, buf);

    printf("Current level is %d for max_indirection %d and type is %d\n", curr_level, max_indirection, type);

    if(curr_level == max_indirection){
        read_data_block(block_num, type);
    }


    else {
        while (offset < (sectors_per_block * sector_size_bytes)){
           int curr_block = read_bytes(buf, offset, 4);
           indirect_traversal(curr_level + 1, max_indirection, curr_block, type);
           offset  = offset + 4;
        }
    }

}

/*write_inode_info(int inode_num, ext2_inode inode){
    int block_group = (inode_num - 1) / super.s_inodes_per_group;
    struct ext2_group_desc gd_info;
    read_gd_info(block_group, &gd_info);
    uint32_t inode_table_start = gd_info.bg_inode_table;
    int inode_index = (inode_num - 1) % super.s_inodes_per_group;
    unsigned char buf[sector_size_bytes];
    read_sectors(partition_start + (inode_table_start * sectors_per_block) + get_inode_sector_offset(super.s_inode_size, inode_index), 
            1, buf);

}*/

void set_directory_entry(int data_block, int directory_number, struct ext2_dir_entry_2 new_entry){
    unsigned char buf[sector_size_bytes * sectors_per_block];
    read_sectors(partition_start + (sectors_per_block * data_block), sectors_per_block, buf);
    int i = 0;
    int offset = 0;
    int dir_length;
    while (i < directory_number){
        dir_length = read_bytes(buf, offset + 4, 2);
        offset = offset + dir_length;
        i++;
    }
    struct ext2_dir_entry_2 *old_entry = (struct ext2_dir_entry_2 *)(buf + offset);
    old_entry->inode = new_entry.inode;
    old_entry->rec_len = new_entry.rec_len;
    old_entry->name_len = new_entry.name_len;
    old_entry->file_type = new_entry.file_type;
    write_sectors(partition_start + (sectors_per_block * data_block), sectors_per_block, buf);
}

void fix_directory_pointers(int inode_num, int parent_num){
    printf("Checking directory pointers for %d\n", inode_num);
    struct ext2_inode i_info;
    read_inode_info(inode_num, &i_info);
    if((i_info.i_mode & 0xf000) == 0x4000){
        int i, j;
        int num_entries;
        for(i = 0; i < 12; i++){
            if(i_info.i_block[i] == 0)
                continue;
            struct ext2_dir_entry_2 *directory_entries;
            int count;
            directory_entries = read_directory_block(i_info.i_block[i], &count);

            for (j = 0; j < count; j++){
                if (directory_entries[j].inode == 0)
                    continue;
                struct ext2_inode dir_inode;
                char names[255];
                int k;

                for(k = 0; k < directory_entries[j].name_len; k++){
                    names[k] = directory_entries[j].name[k];
                }
                names[k] = '\0';

		//Fix any directory pointer issues
                if (!strncmp(names, ".", directory_entries[j].name_len)){
                    if(!(directory_entries[j].inode == inode_num)){
                        printf("Current directory points to %d when it should be %d\n", directory_entries[j].inode, inode_num);
                        directory_entries[j].inode = inode_num;
                        set_directory_entry(i_info.i_block[i], j, directory_entries[j]);
                    }
                }
                if (!strncmp(names, "..", directory_entries[j].name_len)){
                    if(!(directory_entries[j].inode == inode_num)){
                        printf("Parent directory points to %d when it should be %d\n", directory_entries[j].inode, parent_num);
                        directory_entries[j].inode = parent_num;
                        set_directory_entry(i_info.i_block[i], j, directory_entries[j]);
                    }
                }

		printf("Reading inode info for %d\n", directory_entries[j].inode);
                read_inode_info(directory_entries[j].inode, &dir_inode);
		printf("Read inode info for %d\n", directory_entries[j].inode);
                if((dir_inode.i_mode & 0xf000) == 0x4000 && strncmp(names, ".", directory_entries[j].name_len)
                        && strncmp(names, "..", directory_entries[j].name_len))
                    fix_directory_pointers(directory_entries[j].inode, inode_num);
            }

        }

        //Read singly indirect block
        int singly_indirect_block = i_info.i_block[12];
        if (singly_indirect_block != 0){
            indirect_traversal(0, 1, singly_indirect_block, DIRECTORY_DATA_BLOCK);
        }
        
        //Read doubly indirect block
        int doubly_indirect_block = i_info.i_block[13];
        if (doubly_indirect_block != 0){
            indirect_traversal(0, 2, doubly_indirect_block, DIRECTORY_DATA_BLOCK);
        }

        //Read triply indirect block
        int triply_indirect_block = i_info.i_block[14];
        if (triply_indirect_block != 0){
            indirect_traversal(0, 3, triply_indirect_block, DIRECTORY_DATA_BLOCK);
        }
    }
    else if ((i_info.i_mode & 0xf000) == 0x8000){
        //printf("Found file!\n");
    }

}

void traverse_directories(int inode_num){
    printf("Traversing inode number %d\n", inode_num);
    struct ext2_inode i_info;
    read_inode_info(inode_num, &i_info);
    if((i_info.i_mode & 0xf000) == 0x4000){
        int i, j;
        int num_entries;
        for(i = 0; i < 12; i++){
            if(i_info.i_block[i] == 0)
                continue;
            struct ext2_dir_entry_2 *directory_entries;
            int count;
            directory_entries = read_directory_block(i_info.i_block[i], &count);

            for (j = 0; j < count; j++){
		printf("This directory has %d directory entries\n", count);
                if (directory_entries[j].inode == 0)
                    continue;
                struct ext2_inode dir_inode;
                char names[255];
                int k;
		printf("Reading inode info for %d\n", directory_entries[j].inode);
                read_inode_info(directory_entries[j].inode, &dir_inode);
		printf("Read inode info for %d\n", directory_entries[j].inode);
                for(k = 0; k < directory_entries[j].name_len; k++){
                    names[k] = directory_entries[j].name[k];
                }
                names[k] = '\0';
                printf("Found file/dir %s at inode %d\n", names, inode_num);
                if((dir_inode.i_mode & 0xf000) == 0x4000 && strncmp(names, ".", directory_entries[j].name_len)
                        && strncmp(names, "..", directory_entries[j].name_len)){
                    traverse_directories(directory_entries[j].inode);
		}
            }

        }

        //Read singly indirect block
        int singly_indirect_block = i_info.i_block[12];
        if (singly_indirect_block != 0){
            indirect_traversal(0, 1, singly_indirect_block, DIRECTORY_DATA_BLOCK);
        }
        
        //Read doubly indirect block
        int doubly_indirect_block = i_info.i_block[13];
        if (doubly_indirect_block != 0){
            indirect_traversal(0, 2, doubly_indirect_block, DIRECTORY_DATA_BLOCK);
        }

        //Read triply indirect block
        int triply_indirect_block = i_info.i_block[14];
        if (triply_indirect_block != 0){
            indirect_traversal(0, 3, triply_indirect_block, DIRECTORY_DATA_BLOCK);
        }
    }
    else if ((i_info.i_mode & 0xf000) == 0x8000){
        //printf("Found file!\n");
    }

}

struct ext2_dir_entry_2* read_directory_block(int block_num, int *count){
    unsigned char buf[sector_size_bytes * sectors_per_block];
    read_sectors(partition_start + (sectors_per_block * block_num), sectors_per_block, buf);
    int offset = 0;
    int i;
    int j = 0;
    int current_size = 0;
    uint32_t inode_num;
    uint16_t dir_length;
    char name_len;
    char file_type;
    char names[255];
    struct ext2_dir_entry_2 *directories = (struct ext2_dir_entry_2*)malloc(sizeof(struct ext2_dir_entry_2));

    while(offset < (sectors_per_block * sector_size_bytes)){
        struct ext2_dir_entry_2 *entry = (struct ext2_dir_entry_2 *)malloc(sizeof(struct ext2_dir_entry_2));
        inode_num = read_bytes(buf, offset, 4);
        dir_length = read_bytes(buf, offset + 4, 2);
        name_len = read_bytes(buf, offset + 6, 1);
        file_type = read_bytes(buf, offset + 7, 1);

        entry->inode = inode_num;
        entry->rec_len = dir_length;
        entry->name_len = name_len;
        entry->file_type = file_type;
        for (i = 0; i < name_len; i++){
            names[i] = *(buf + offset + 8 + i);
            entry->name[i] = *(buf + offset + 8 + i);
        }
        names[i] = '\0';
        offset = offset + dir_length;
        directories = realloc(directories, (current_size + 1) * sizeof(struct ext2_dir_entry_2));
        current_size++;
        directories[j++] = *entry;
    }
    *count = j;
    return directories;
}

/*void print_inode_of_file(uint32_t inode_num, char *path[]){
    struct ext2_inode i_info;
    read_inode_info(inode_table_start, inode_num, &i_info, 
            &gd_info, &super, partition_start);
    printf("Inode mode is: %d\n", i_info.i_mode);
}*/

void read_data_block(uint32_t block_num, db_type type){
    if (type == DIRECTORY_DATA_BLOCK){
        //printf("Reading directory data block %d\n", block_num);
        unsigned char buf[sector_size_bytes * sectors_per_block];
        read_sectors(partition_start + (sectors_per_block * block_num), sectors_per_block, buf);
        //printf("Read sector %d\n", partition_start + (sectors_per_block * block_num));
        int offset = 0;
        uint16_t dir_length;

        //char lions[5] = {'l', 'i', 'o', 'n', 's'};
        char names[100];
        int i;
        int name_len;
        char c;
        int inode_num;

        while(offset < (sectors_per_block * sector_size_bytes)){
            name_len = read_bytes(buf, offset + 6, 1);
            //printf("Name length is %d\n", read_bytes(buf, offset + 6, 1));
            for (i = 0; i < name_len; i++)
                names[i] = *(buf + offset + 8 + i);
            names[i] = '\0';
            inode_num = read_bytes(buf, offset, 4);
            //if (inode_num == 0)
            //    continue;
            if(!strncmp(".", buf + offset + 8, name_len) || !strncmp("..", buf + offset + 8, name_len) || inode_num == 0){
                if (inode_num != 0)
                    printf("Found dir/file %s at inode %d\n", names, inode_num);
                dir_length = read_bytes(buf, offset + 4, 2);
                offset = offset + dir_length;
                //printf("Offset is %d\n", offset);
                continue;
            }
            printf("Found dir/file %s at inode %d\n", names, inode_num);
            traverse_directories(inode_num);
            //printf("Directory name is %s\n", offset + 8);
            //if(!strncmp(lions, buf + offset + 8, 5)){
                //printf("Lions found at inode %d\n", read_bytes(buf, offset, 4));
            //}
            dir_length = read_bytes(buf, offset + 4, 2);
            offset = offset + dir_length;
            //printf("Offset is %d\n", offset);
        }
        //c = getchar();
        //c = c;
    }
    else {
        //printf("File data block found\n");
    }
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

/* write_sectors: write a buffer into a specified number of sectors.
 *
 * inputs:
 *   int64 start_sector: the starting sector number to write.
 *                	sector numbering starts with 0.
 *   int numsectors: the number of sectors to write.  must be >= 1.
 *   void *from: the requested number of sectors are copied from here.
 *
 * outputs:
 *   int device [GLOBAL]: the disk into which to write.
 *
 * modifies:
 *   int device [GLOBAL]
 */
void write_sectors (int64_t start_sector, unsigned int num_sectors, void *from)
{
    ssize_t ret;
    int64_t lret;
    int64_t sector_offset;
    ssize_t bytes_to_write;

    if (num_sectors == 1) {
        printf("Reading sector  %"PRId64"\n", start_sector);
    } else {
        printf("Reading sectors %"PRId64"--%"PRId64"\n",
               start_sector, start_sector + (num_sectors - 1));
    }

    sector_offset = start_sector * sector_size_bytes;

    if ((lret = lseek64(device, sector_offset, SEEK_SET)) != sector_offset) {
        fprintf(stderr, "Seek to position %"PRId64" failed: "
                "returned %"PRId64"\n", sector_offset, lret);
        exit(-1);
    }

    bytes_to_write = sector_size_bytes * num_sectors;

    if ((ret = write(device, from, bytes_to_write)) != bytes_to_write) {
        fprintf(stderr, "Write sector %"PRId64" length %d failed: "
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

void read_gd_info(int block_group, struct ext2_group_desc *gd_info) {
    //unsigned char buf[sector_size_bytes * sectors_per_block];
    int offset = block_group * 32;
    //read_sectors(partition_start + (sectors_per_block * 2), sectors_per_block, buf);
    gd_info->bg_block_bitmap = read_bytes(group_descriptor_table, offset+0, 4);
    gd_info->bg_inode_bitmap = read_bytes(group_descriptor_table, offset+4, 4);
    gd_info->bg_inode_table = read_bytes(group_descriptor_table, offset+8, 4);
    gd_info->bg_free_blocks_count = read_bytes(group_descriptor_table, offset+12, 2);
    gd_info->bg_free_inodes_count = read_bytes(group_descriptor_table, offset+14, 2);
    return;
}

uint32_t get_inode_sector_offset(uint32_t inode_size, uint32_t inode_index) {
    return inode_index/(sector_size_bytes/inode_size);
}

void read_inode_info(uint32_t inode_num, struct ext2_inode *i_info) {
    int block_group = (inode_num - 1) / super.s_inodes_per_group;
    struct ext2_group_desc gd_info;
    read_gd_info(block_group, &gd_info);
    uint32_t inode_table_start = gd_info.bg_inode_table;
    int inode_index = (inode_num - 1) % super.s_inodes_per_group;
    unsigned char buf[sector_size_bytes];
    read_sectors(partition_start + (inode_table_start * sectors_per_block) + get_inode_sector_offset(super.s_inode_size, inode_index), 
            1, buf);
    //printf("Read sector %d\n", partition_start + (i_block_start * sectors_per_block) + get_inode_sector_offset(super.s_inode_size, inode_index));
    uint32_t num_inodes_sector = sector_size_bytes / super.s_inode_size;
    uint32_t offset = ((inode_index % num_inodes_sector)) * super.s_inode_size; 
    //printf("Inode number is %d\n", inode_index);
    //printf("Offset is %d\n", offset);
    i_info->i_mode = read_bytes(buf, offset + 0, 2);
    i_info->i_size = read_bytes(buf, offset + 4, 4);
    int i;
    for(i = 0; i < 15; i++){
        i_info->i_block[i] = read_bytes(buf, offset + 40 + (i * 4), 4);
    }    
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

