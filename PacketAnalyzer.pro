QT += core widgets

CONFIG += c++17

TARGET = PacketAnalyzer
TEMPLATE = app

SOURCES += main.cpp

# Platform-specific libraries
unix {
    LIBS += -lpcap
}

win32 {
    LIBS += -lwpcap -lPacket -lws2_32 -liphlpapi
    INCLUDEPATH += "C:/npcap-sdk/Include"
    LIBPATH += "C:/npcap-sdk/Lib/x64"
}

# Compiler flags
QMAKE_CXXFLAGS += -Wall -Wextra

# Install
target.path = /usr/local/bin
INSTALLS += target