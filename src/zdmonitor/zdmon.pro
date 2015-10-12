#-------------------------------------------------
#
# Project created by QtCreator 2015-10-03T15:00:22
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = zdmon
TEMPLATE = app


SOURCES += zdmon_main.cpp zdmon.cpp zoneswidget.cpp

HEADERS  += zdmon.h zoneswidget.h

FORMS    += zdmon.ui

QMAKE_CFLAGS   += -g -O0
QMAKE_CXXFLAGS += -g -O0
