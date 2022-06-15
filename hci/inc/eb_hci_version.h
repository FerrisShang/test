#ifndef __EB_HCI_VERSION_H__
#define __EB_HCI_VERSION_H__

#define BLUETOOTH_VER_1_0B          0
#define BLUETOOTH_VER_1_1           1
#define BLUETOOTH_VER_1_2           2
#define BLUETOOTH_VER_2_0           3
#define BLUETOOTH_VER_2_1           4
#define BLUETOOTH_VER_3_0           5
#define BLUETOOTH_VER_4_0           6
#define BLUETOOTH_VER_4_1           7
#define BLUETOOTH_VER_4_2           8
#define BLUETOOTH_VER_5_0           9
#define BLUETOOTH_VER_5_1           10
#define BLUETOOTH_VER_5_2           11
#define BLUETOOTH_VER_5_3           12

#define BLUETOOTH_VER_1_0B_STR     "Bluetooth Core Specification 1.0b (Withdrawn)"
#define BLUETOOTH_VER_1_1_STR      "Bluetooth Core Specification 1.1 (Withdrawn)"
#define BLUETOOTH_VER_1_2_STR      "Bluetooth Core Specification 1.2 (Withdrawn)"
#define BLUETOOTH_VER_2_0_STR      "Bluetooth Core Specification 2.0 + EDR (Withdrawn)"
#define BLUETOOTH_VER_2_1_STR      "Bluetooth Core Specification 2.1 + EDR (Withdrawn)"
#define BLUETOOTH_VER_3_0_STR      "Bluetooth Core Specification 3.0 + HS (Withdrawn)"
#define BLUETOOTH_VER_4_0_STR      "Bluetooth Core Specification 4.0"
#define BLUETOOTH_VER_4_1_STR      "Bluetooth Core Specification 4.1"
#define BLUETOOTH_VER_4_2_STR      "Bluetooth Core Specification 4.2"
#define BLUETOOTH_VER_5_0_STR      "Bluetooth Core Specification 5.0"
#define BLUETOOTH_VER_5_1_STR      "Bluetooth Core Specification 5.1"
#define BLUETOOTH_VER_5_2_STR      "Bluetooth Core Specification 5.2"
#define BLUETOOTH_VER_5_3_STR      "Bluetooth Core Specification 5.3"

#define BLUETOOTH_VER_DEFINE \
{ \
    { BLUETOOTH_VER_1_0B,        BLUETOOTH_VER_1_0B_STR },  \
    { BLUETOOTH_VER_1_1,         BLUETOOTH_VER_1_1_STR  },  \
    { BLUETOOTH_VER_1_2,         BLUETOOTH_VER_1_2_STR  },  \
    { BLUETOOTH_VER_2_0,         BLUETOOTH_VER_2_0_STR  },  \
    { BLUETOOTH_VER_2_1,         BLUETOOTH_VER_2_1_STR  },  \
    { BLUETOOTH_VER_3_0,         BLUETOOTH_VER_3_0_STR  },  \
    { BLUETOOTH_VER_4_0,         BLUETOOTH_VER_4_0_STR  },  \
    { BLUETOOTH_VER_4_1,         BLUETOOTH_VER_4_1_STR  },  \
    { BLUETOOTH_VER_4_2,         BLUETOOTH_VER_4_2_STR  },  \
    { BLUETOOTH_VER_5_0,         BLUETOOTH_VER_5_0_STR  },  \
    { BLUETOOTH_VER_5_1,         BLUETOOTH_VER_5_1_STR  },  \
    { BLUETOOTH_VER_5_2,         BLUETOOTH_VER_5_2_STR  },  \
    { BLUETOOTH_VER_5_3,         BLUETOOTH_VER_5_3_STR  },  \
}

#endif /* __EB_HCI_VERSION_H__ */
