# PixelExperience Android 13 private AVB configuration.
# Include this at the END of the final bonito/sargo BoardConfig chain.
#
# IMPORTANT: remove release-unsafe --flags 3 from the device tree rather than
# trying to hide it here.

PRIVATE_AVB_KEY ?= vendor/priv/keys/avb.pem
PRIVATE_AVB_ALGORITHM ?= SHA256_RSA4096

# Catch the common disable forms at make time. audit_integration.py and
# sign_release.py perform a numeric bit-mask check as well.
ifneq ($(findstring --flags 1,$(BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS)),)
$(error private signing: AVB hashtree is disabled (--flags 1))
endif
ifneq ($(findstring --flags=1,$(BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS)),)
$(error private signing: AVB hashtree is disabled (--flags=1))
endif
ifneq ($(findstring --flags 2,$(BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS)),)
$(error private signing: AVB verification is disabled (--flags 2))
endif
ifneq ($(findstring --flags=2,$(BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS)),)
$(error private signing: AVB verification is disabled (--flags=2))
endif
ifneq ($(findstring --flags 3,$(BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS)),)
$(error private signing: AVB verification+hashtree are disabled (--flags 3))
endif
ifneq ($(findstring --flags=3,$(BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS)),)
$(error private signing: AVB verification+hashtree are disabled (--flags=3))
endif
ifneq ($(findstring --flags 0x1,$(BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS)),)
$(error private signing: AVB hashtree is disabled (--flags 0x1))
endif
ifneq ($(findstring --flags 0x2,$(BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS)),)
$(error private signing: AVB verification is disabled (--flags 0x2))
endif
ifneq ($(findstring --flags 0x3,$(BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS)),)
$(error private signing: AVB verification+hashtree are disabled (--flags 0x3))
endif
ifneq ($(findstring --set_hashtree_disabled_flag,$(BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS)),)
$(error private signing: --set_hashtree_disabled_flag is not release-safe)
endif

ifeq ($(strip $(BOARD_AVB_ENABLE)),true)
BOARD_AVB_ALGORITHM := $(PRIVATE_AVB_ALGORITHM)
BOARD_AVB_KEY_PATH := $(PRIVATE_AVB_KEY)

# Preserve the topology declared by the device. Only replace chained slots
# that actually exist in this tree.
ifneq ($(strip $(BOARD_AVB_VBMETA_SYSTEM)),)
BOARD_AVB_VBMETA_SYSTEM_KEY_PATH := $(PRIVATE_AVB_KEY)
BOARD_AVB_VBMETA_SYSTEM_ALGORITHM := $(PRIVATE_AVB_ALGORITHM)
endif
ifneq ($(strip $(BOARD_AVB_VBMETA_VENDOR)),)
BOARD_AVB_VBMETA_VENDOR_KEY_PATH := $(PRIVATE_AVB_KEY)
BOARD_AVB_VBMETA_VENDOR_ALGORITHM := $(PRIVATE_AVB_ALGORITHM)
endif
ifneq ($(strip $(BOARD_AVB_RECOVERY_KEY_PATH)),)
BOARD_AVB_RECOVERY_KEY_PATH := $(PRIVATE_AVB_KEY)
BOARD_AVB_RECOVERY_ALGORITHM := $(PRIVATE_AVB_ALGORITHM)
endif
else
$(warning vendor/priv/keys/BoardConfigPrivKeys.mk: BOARD_AVB_ENABLE is not true; AVB override inactive)
endif
