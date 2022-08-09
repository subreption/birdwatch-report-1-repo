/*
 * Copyright (c) 2022 Subreption LLC. All rights reserved.
 * Licensed under the Subreption Ukraine Defense License Version 1.0.
 *
 *  “To be a man is, precisely, to be responsible. It is to feel shame at the
 *     sight of what seems to be unmerited misery. It is to take pride in a
 *      victory won by one's comrades. It is to feel, when setting one's stone,
 *       that one is contributing to the building of the world.”
 *   ― from Wind, Sand and Stars by Antoine de Saint-Exupéry (RIP, WW2)
 *
 * Author: LH
 *
 * This program makes some assumptions about vsks:
 *  - It uses the ioctl() request ID reverse engineered from the VSKS kernel module.
 *  - It uses the commands reverse engineered from the VSKS kernel module.
 *  - It takes some information and code (adapted) from [REDACTED :>] in a captured
 *    Orlan 10's mainboard. 
 *  - This needs to run *inside* the Orlan 10 system with functional mainboard
 *    and its peripherals, attached to the VSKS carrier.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>
#include <sys/syscall.h>
#include <pthread.h>

const char *progversion = "0.2";
const char *copyright = "Copyright (c) 2022 Subreption LLC. All rights reserved.";

#define VSKS_COMMAND_REBOOT         0xc1000000UL
#define VSKS_COMMAND_CONNECT_NOR    0xc0000000UL

const char *VSKS_SPI_DEVICE             = "/dev/spidev1.0";
const char *VSKS_COM_DEVICE             = "/dev/COM-1A";
const char *VSKS_PLINKA_DEVICE          = "/dev/PLINKA";

const char *FLASHROM_EXE                = "./flashrom";
const char *FLASHROM_OUTPUT             = "vsks_fw.bin";

const char *unwanted_tenants[] = {
    "/root/bin/pw",
    "/usr/bin/ktrmultiplex",
    NULL
};

struct gpmc_arg {
    int first;
    unsigned int second;
};

unsigned int tenant_status;

/* msleep(): Sleep for the requested number of milliseconds. */
int msleep(long msec)
{
    struct timespec ts;
    int res;

    if (msec < 0)
    {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}

struct linux_dirent64 {
    long           d_ino;    /* 64-bit inode number */
    off_t          d_off;    /* 64-bit offset to next structure */
    unsigned short d_reclen; /* Size of this dirent */
    unsigned char  d_type;   /* File type */
    char           d_name[]; /* Filename (null-terminated) */
};

static int remove_unwanted_tenants(void)
{
    int i;
    int fd;
    int dirent_read = 0;
    int err         = 0;
    char buf[1024];
    char pspath[256];
    char exepath[1024];
    ssize_t namelen;
    struct linux_dirent64* entry;

    fd = open("/proc", O_RDONLY | O_DIRECTORY);
    if (fd == -1) {
        perror("open");
        return 1;
    }

    for (;;) {
        dirent_read =
          syscall(SYS_getdents64, fd, buf, sizeof(buf));
        if (dirent_read == -1) {
            perror("SYS_getdents64");
            err = 1;
            break;
        }

        if (dirent_read == 0) {
            err = 0;
            break;
        }

        for (int off = 0; off < dirent_read;)
        {
            int pid;

            entry = (struct linux_dirent64 *)(buf + off);

            pid = atoi(entry->d_name);
            if (pid && pid > 10)
            {
                snprintf(pspath, sizeof(pspath) - 1, "/proc/%s/exe", entry->d_name);
                pspath[sizeof(pspath) - 1] = '\0';

                namelen = readlink(pspath, exepath, sizeof(exepath) - 1);
                if (namelen)
                {
                    exepath[namelen] = '\0';

                    for (i = 0; i < sizeof(unwanted_tenants) / sizeof(char *); i++)
                    {
                        if (unwanted_tenants[i] == NULL)
                            break;

                        if (!strcmp(exepath, unwanted_tenants[i]))
                        {
                            printf("[*] Terminating %s (pid %d)...\n",
                                exepath, pid);
                            kill(pid, SIGINT);
                            kill(pid, SIGTERM);
                            break;
                        }
                    }
                }
            }

            off += entry->d_reclen;
        }
    }

    close(fd);
}

static void *jealous_tenant(void *arg)
{
    int i;
    unsigned int *status = (unsigned int *) arg;

    printf("[*] Jealous tenant running, watching for:\n");

    for (i = 0; i < sizeof(unwanted_tenants) / sizeof(char *); i++)
    {
        if (unwanted_tenants[i] != NULL)
            printf("   %s\n", unwanted_tenants[i]);
    }

    while (*status < 2)
    {
        /* prevent stc's init from respawning these dirty squatters */
        kill(1, SIGSTOP);
        remove_unwanted_tenants();
        msleep(10);
    }

    return NULL;
}


/* The magic:
 *
 * if (cmd == 0x4008567c) {
 *   iVar3 = *(int *)arg;
 *   uVar2 = *(uint *)(arg + 4);
 *   if (iVar3 == 2) {
 *     uVar2 = uVar2 | 0x400000;
 *   }
 *   uVar4 = _raw_spin_lock_irqsave(&global_lock);
 *   DataSynchronizationBarrier(0xf);
 *   if (___arm_ioremap != NULL) {
 *     (*___arm_ioremap)();
 *   }
 *   *(uint *)(ctl_addr + (iVar3 + devidx * 0x400 + 6) * 4) = uVar2;
 *   _raw_spin_unlock_irqrestore(&global_lock,uVar4);
 *   return 1;
 * }
 */

int vsks_fpga_ioctl(int fd, int param_2, unsigned int param_3)
{
    int err = 0;

    struct gpmc_arg arg;

    arg.first = param_2; 
    arg.second = param_3;

    err = ioctl(fd, 0x4008567cUL, &arg);
    if (err < 0)
        perror("ioctl");

    return err;
}

static int check_nor_working(void)
{
    int err = 0;
    int ret = 0;
    int i;
    int fd;
    uint8_t bits = 8;
    uint8_t mode= SPI_MODE_3;
    uint32_t speed = 1000000;
    unsigned char txbuf[20];
    unsigned char rxbuf[20];

    struct spi_ioc_transfer tr = {
            .tx_buf = (unsigned long) txbuf,
            .rx_buf = (unsigned long) rxbuf,
            .len = 4,
            .delay_usecs = 0,
            .speed_hz = speed,
            .bits_per_word = bits,
    };

    memset(txbuf, 0, sizeof(txbuf));
    memset(rxbuf, 0, sizeof(rxbuf));

    fd = open(VSKS_SPI_DEVICE, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "[!] Can't open %s device\n", VSKS_SPI_DEVICE);
        return 1;
    }

    err = ioctl(fd, SPI_IOC_WR_MODE, &mode);
    if (err == -1) {
        fprintf(stderr, "[!] Can't set SPI_IOC_WR_MODE\n");
        ret = 1;
        goto out;
    }
    else {
        err = ioctl(fd, SPI_IOC_RD_MODE, &mode);
        if (err == -1) {
          fprintf(stderr, "[!] Can't set SPI_IOC_RD_MODE\n");
          ret = 1;
        }
        else {
            err = ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
            if (err == -1) {
                fprintf(stderr, "[!] Can't set SPI_IOC_WR_BITS_PER_WORD\n");
                ret = 1;
            }
            else {
                err = ioctl(fd, SPI_IOC_RD_BITS_PER_WORD, &bits);
                if (err == -1) {
                    fprintf(stderr, "[!] Can't set SPI_IOC_RD_BITS_PER_WORD\n");
                    ret = 1;
                }
                else {
                    err = ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
                    if (err == -1) {
                        fprintf(stderr, "[!] Can't set SPI_IOC_WR_MAX_SPEED_HZ\n");
                        ret = 1;
                    }
                    else {
                        err = ioctl(fd, SPI_IOC_RD_MAX_SPEED_HZ, &speed);
                        if (err == -1) {
                            fprintf(stderr, "[!] Can't set SPI_IOC_RD_MAX_SPEED_HZ\n");
                            ret = 1;
                        }
                        else
                        {
                            printf("[*] SPI mode %d bits %d speed %d Hz\n",
                                (uint8_t) mode, (uint8_t) bits, speed);

                            for (i = 0; i < 0x10; i++)
                            {
                                /* READ_ID operation */
                                txbuf[0] = 0x9E;
                                tr.bits_per_word = bits;
                                tr.speed_hz = speed;

                                err = ioctl(fd, SPI_IOC_MESSAGE(2), &tr);
                                if (err == -1) {
                                    fprintf(stderr, "[!] Error reading NOR via SPI\n");
                                    ret = 1;
                                    goto out;
                                }
                            }

                            /*  Read ID Data: manufacturer ID, memory type, capacity=128Mb */
                            if ((rxbuf[0] == '\x20') && (rxbuf[1] == '\xbb') && (rxbuf[2] == '\x18'))
                            {
                                printf("[*] N25Q128 ready. Bitstream can be dumped.\n");
                                ret = 0;
                                goto out;
                            }
                        }

                        fprintf(stderr, "[!] N25Q128 not found\n");
                        ret = 1;
                    }
                }
            }
        }
    }

    goto out;

out:
    if (fd)
        close(fd);

    return ret;
}

int vsks_fpga_connect_nor_to_spi(int fd)
{
    int err = 0;

    printf("[+] Connecting VSKS NOR to %s...\n", VSKS_SPI_DEVICE);

    /* send the connect command */
    err = vsks_fpga_ioctl(fd, 0, VSKS_COMMAND_CONNECT_NOR);
    if (err) {
        fprintf(stderr, "[!] Failed to send connect command\n");
        return -1;
    }

    /* we don't error check these */
    vsks_fpga_ioctl(fd, 1, 1);
    vsks_fpga_ioctl(fd, 2, 0x200000);

    /* if all went well, NOR is now connected SPI1.0 */
    return err;
}

int vsks_fpga_reboot(int fd)
{
    int err = 0;

    printf("[+] Rebooting VSKS FPGA...\n");

    /* send the reboot command */
    err = vsks_fpga_ioctl(fd, 0, VSKS_COMMAND_REBOOT);
    if (err) {
        fprintf(stderr, "[!] Failed to send reboot command\n");
        return -1;
    }


    return err;
}

int vsks_fpga_connect(bool silent)
{
    int i;
    int ret    = 0;
    int fd     = -1;
    const char *vsks_dev_nodes[] = {
        VSKS_COM_DEVICE,
        VSKS_PLINKA_DEVICE,
        "/dev/DVBS1A",
        NULL
    };

    for (i = 0; i < sizeof(vsks_dev_nodes) / sizeof(char *); i++)
    {
        const char *devname = vsks_dev_nodes[i];

        if (devname == NULL)
            break;

        if (!silent)
            printf("[+] Trying to open %s...", devname);

        fd = open(devname, 2);
        if (fd > 0) {
            if (!silent)
                printf(" opened.\n");

            break;
        } else {
            if (!silent)
                printf(" failed.\n");

            if (access(devname, F_OK) != 0) {
                fd = -1000;
                break;
            }

            continue;
        }
    }

    return fd;
}

static int exec_prog(const char **argv)
{
    pid_t   my_pid;
    int     status, timeout;

    if (0 == (my_pid = fork()))
    {
        if (-1 == execve(argv[0], (char **)argv , NULL))
        {
            perror("execve");
            return -1;
        }
    }

    /* 15 minutes seems more than sensible */
    timeout = 60 * 15;

    while (0 == waitpid(my_pid , &status , WNOHANG))
    {
        if (--timeout < 0) {
            return -1;
        }

        msleep(1000);
    }

    if (1 != WIFEXITED(status) || 0 != WEXITSTATUS(status)) {
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    int ret = 0;
    int fd = -1;
    int i = 0;
    pthread_t jt_thread;

    printf("[*] LH vs. VSKS Chapter. 1 (v.%s)\n", progversion);
    printf("[*] %s\n", copyright);

    fd = vsks_fpga_connect(false);
    if (fd < 1)
    {
        if (fd == -1000) {
            fprintf(stderr, "[!] Devices not present, is vsks module loaded?\n");
            fprintf(stderr, "[!] This tool will not work outside of ORLAN-x systems.\n");
            ret = -1;
            goto out;
        }

        printf("[!] VSKS device in use, attempting workaround...\n");

        /* launch the jealous tenant, circling vsks like a true shithawk */
        tenant_status = 0;
        pthread_create(&jt_thread, NULL, &jealous_tenant, &tenant_status);
        
        /* try 10 times */
        for (i = 0; i < 10; i++)
        {
            msleep(200);

            fd = vsks_fpga_connect(true);
            if (fd < 2) {
                continue;
            }

            /* we got it */
            break;
        }

        if (fd < 0) {
            fprintf(stderr, "[!] All %d attempts to open device failed.\n", i);
            goto out;
        }
    }

    ret = vsks_fpga_connect_nor_to_spi(fd);
    if (ret) {
        fprintf(stderr, "[!] Failed to connect NOR.\n");
        goto out;
    }

    printf("[*] Verifying NOR access via %s... ", VSKS_SPI_DEVICE);
    ret = check_nor_working();
    if (!ret) {
        printf("[*] SUCCESS. NOR is ready for access.\n");
    } else {
        fprintf(stderr, "[!] Failed to verify NOR access.\n");
        goto out;
    }

    if (access(FLASHROM_EXE, F_OK) == 0)
    {
        /* flashrom exists, let's execute it and wait for it to finish */

        /* like so: /root/bin/flashrom -p linux_spi:dev="/dev/spidev1.0" -c "N25Q128..1E" -r vsks_fw.bin */
        const char *flashrom_argv[] = {
            FLASHROM_EXE,
            "-p",
            "linux_spi:dev=/dev/spidev1.0",
            "-c",
            "N25Q128..1E",
            "-r",
            FLASHROM_OUTPUT,
            NULL
        };

        ret = exec_prog(flashrom_argv);
        if (!ret) {
            printf("[*] VSKS FPGA NOR successfully dumped to `%s`.\n",
                FLASHROM_OUTPUT);
        } else {
            fprintf(stderr, "[!] %s failed, dump manually and diagnose.\n",
                FLASHROM_EXE);
        }

        /* reboot the FPGA or attempt to */
        ret = vsks_fpga_reboot(fd);
        if (ret < 0) {
            fprintf(stderr, "[!] Rebooting FPGA failed, might need to power cycle (!!!!).\n");
            goto out;
        }

        printf("[*] Rebooted. NOR no longer connected to %s!\n", VSKS_SPI_DEVICE);
        printf("[*] Collect %s and store away in a safe place.\n", FLASHROM_OUTPUT);
        /* muleron, you could have had any flavors, but you chose salty, old man */
        /* why is it that the toughest kids online
                are the ones who cant punch
                    their way out of a paper bag 
                        - anonymous jazzy proverb */
    }

    goto out;

out:
    tenant_status = 100;

    if (fd)
        close(fd);

    exit(ret);
    return ret;
}
