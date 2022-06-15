from building import *

cwd = GetCurrentDir()
src = Split('')
inc = Split('')
CPPDEFINES = []

src_common = []
inc_common = []

src = Split('''
        ./main/main.c
        ./l2cap/eb_l2cap.c
        ./att/eb_att.c
        ./gatt/eb_gatt.c
        ./smp/eb_smp.c
        ./smp/eb_smp_alg.c
        ./smp/smp_aes/eb_smp_aes_soft.c
        ./smp/smp_aes/smp_aes.c
        ./smp/smp_rand/eb_smp_rand_soft.c
        ./module/event/eb_event.c
        ./module/block_buffer/block_ringbuf.c
        ./module/timer/eb_timer.c
        ./module/schedule/eb_pending_linux.c
        ./module/schedule/eb_schedule.c
        ./module/h4tl/btsnoop_rec.c
        ./module/h4tl/eb_h4tl.c
        ./module/alarm/eb_alarm_linux.c
        ./module/hci_interface/linux_udp/linux_udp_client.c
        ./hci/eb_hci.c
        ''')
inc = Split('''
        .
        l2cap
        att
        gatt
        smp
        smp/smp_aes
        smp/smp_rand
        main
        module
        module/event
        module/block_buffer
        module/timer
        module/schedule
        module/h4tl
        module/alarm
        module/hci_interface/linux_udp
        module/hci_interface/linux_usb
        hci
        hci/inc
        ''')

src += src_common
inc += inc_common

group = DefineGroup('ble_app_example', src, inc, CPPDEFINES = CPPDEFINES)

Return('group')

