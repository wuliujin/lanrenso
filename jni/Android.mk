LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := memoryreader
LOCAL_SRC_FILES := memory_reader.c

LOCAL_CFLAGS += -std=c99

LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)
