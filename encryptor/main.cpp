//
//  main.cpp
//  encryptor
//
//  Created by svc64 on 9/27/20.
//

#include <iostream>
#include <sys/stat.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
uint32_t key;
int main(int argc, const char * argv[]) {
    if(argc<2) {
        printf("specify a mach-o path\n");
        exit(1);
    }
    const char * path = argv[1];
    // get file size
    struct stat statResult;
    int err = stat(path, &statResult);
    if(err) {
        printf("stat error %d\n", err);
    }
    FILE * fp = fopen(path, "rb");
    void * macho = malloc(statResult.st_size);
    // read the whole file
    fread(macho, 1, statResult.st_size, fp);
    int32_t magic = FAT_CIGAM;
    if(memcmp(macho, &magic, sizeof(FAT_CIGAM))==0) {
        printf("unsupported fat file!\n");
        fclose(fp);
        free(macho);
        return 1;
    }
    magic = MH_MAGIC_64;
    if(memcmp(macho, &magic, sizeof(MH_MAGIC_64))==0) {
        printf("supported mach-o detected\n");
        struct mach_header_64 * header = (mach_header_64 *)macho;
        printf("load commands: %d size: %d\n", header->ncmds, header->sizeofcmds);
        void * loadCommands = (void*)((uint64_t)macho+sizeof(mach_header_64));
        printf("load commands offset: 0x%llx\n", (uint64_t)loadCommands-(uint64_t)macho);
        // find __TEXT
        uint64_t currentOffset = 0; // the offset of the current load command we're looking at
        while(currentOffset<header->sizeofcmds) {
            struct load_command * loadCommand = (struct load_command *)((uint64_t)loadCommands+currentOffset);
            // we only care about LC_SEGMENT_64
            if(loadCommand->cmd==LC_SEGMENT_64) {
                struct segment_command_64 * segCommand = (struct segment_command_64 *)((uint64_t)loadCommands+currentOffset);
                if(strcmp(segCommand->segname, "__TEXT")==0) {
                    printf("found __TEXT, starts at 0x%llx with VM address 0x%llx\n" , segCommand->fileoff, segCommand->vmaddr);
                    // find the __text section
                    struct section_64 * sections = (struct section_64 *)((uint64_t)segCommand+sizeof(struct segment_command_64));
                    for(int i=0;i<segCommand->nsects;i++) {
                        printf("%s\n", sections[i].sectname);
                        if(strcmp(sections[i].sectname, "__text")==0) {
                            printf("found the __text section, starts at 0x%x, size 0x%llx\n", sections[i].offset, sections[i].size);
                            key = arc4random();
                            printf("your key: 0x%x\n", key);
                            // XOR the text section
                            for(uint32_t x=sections[i].offset;x<sections[i].offset+sections[i].size;x+=sizeof(uint32_t)) {
                                if(x+sizeof(uint32_t)-sections[i].offset>sections[i].size) { // bounds test
                                    printf("we're at the end!");
                                }
                                uint32_t toEncrypt;
                                memcpy(&toEncrypt, (void *)(x+(uint64_t)macho), sizeof(uint32_t));
                                toEncrypt = toEncrypt^key;
                                memcpy((void *)(x+(uint64_t)macho), &toEncrypt, sizeof(uint32_t));
                                
                            }
                            goto end;
                        }
                    }
                }
            }
            currentOffset+=loadCommand->cmdsize;
        }
    end:
        fclose(fp);
        // write the key
        fp = fopen("key", "wb");
        fwrite(&key, 1,sizeof(key), fp);
        fclose(fp);
        fp = fopen(path, "wb");
        fwrite(macho, 1, statResult.st_size, fp);
        fclose(fp);
        free(macho);
        return 0;
    }
    //struct mach_header * header = (struct mach_header *)macho;
    printf("wtf is this\n");
    return 69;
}
