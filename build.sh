rm -rf a.out
gcc -Wall -pthread -O0 -g -fsanitize=address -static-libasan -lasan \
    ./main/main.c \
    ./l2cap/eb_l2cap.c \
    ./att/eb_att.c \
    ./gatt/eb_gatt.c \
    ./smp/eb_smp.c \
    ./smp/eb_smp_alg.c \
    -D_SMP_ALG_HCI_ENC \
    ./smp/smp_aes/eb_smp_aes_soft.c \
    ./smp/smp_aes/smp_aes.c \
    ./smp/smp_rand/eb_smp_rand_soft.c \
    ./module/event/eb_event.c \
    ./module/block_buffer/block_ringbuf.c \
    ./module/timer/eb_timer.c \
    ./module/schedule/eb_pending_linux.c \
    ./module/schedule/eb_schedule.c \
    ./module/h4tl/btsnoop_rec.c \
    ./module/h4tl/eb_h4tl.c \
    ./module/alarm/eb_alarm_linux.c \
    ./module/hci_interface/linux_udp/linux_udp_client.c \
    ./hci/eb_hci.c \
    -I. \
    -Il2cap \
    -Iatt \
    -Igatt \
    -Ismp \
    -Ismp/smp_aes \
    -Ismp/smp_rand \
    -Imain \
    -Imodule \
    -Imodule/event \
    -Imodule/memory \
    -Imodule/debug \
    -Imodule/block_buffer \
    -Imodule/timer \
    -Imodule/schedule \
    -Imodule/h4tl \
    -Imodule/alarm \
    -Imodule/hci_interface/linux_udp \
    -Imodule/hci_interface/linux_usb \
    -Ihci \
    -Ihci/inc \
    -DCONFIG_BTSNOOP \

#    ./module/hci_interface/linux_usb/linux_usb_hci.c -lusb-1.0\

