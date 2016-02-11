/*
 * Visual Monitor for ZDM: Kernel Device Mapper
 *
 * Copyright (C) 2015 Seagate Technology PLC
 *
 * Written by:
 * Shaun Tancheff <shaun.tancheff@seagate.com>
 *
 * This file is licensed under  the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef _ZONESWIDGET_H_
#define _ZONESWIDGET_H_

#include <QCloseEvent>
#include <QShowEvent>
#include <QPaintEvent>
#include <QMouseEvent>
#include <QAction>
#include <QColor>
#include <QList>
#include <QMap>
#include <QString>
#include <QDebug>

#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <errno.h>
#include <string.h> // strdup
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>

#include <zdmioctl.h>

// CentOS g++ is funky

#ifndef PRIu64
#define PRIu64 "llu"
#endif


/**
 */
class ZonesWidget : public QWidget
{
    Q_OBJECT
public:
    ZonesWidget(QWidget *parent=0);

    int setDevice(QString zdmDevice);
    int updateView(int zoom);
    int getMZCount(void);
    struct megazone_info * getMZData(void);
    virtual QSize sizeHint();
    virtual QSize minimumSizeHint();

protected:
    virtual void resizeEvent(QResizeEvent *event);
    virtual void paintEvent(QPaintEvent *e);
    void doPaint(QPaintEvent *e);
    void doDrawZones(QPainter& painter, QRect& area);
    int updatePlaybackView();
    int updateFakeDemoView();
    int updateLiveDeviceView();

    int openProcWpEntry(QString zdmDevice);
    int openProcUsedEntry(QString zdmDevice);
    int openProcStatusEntry(QString zdmDevice);
    int getLiveDeviceDataIoctl();
    int getLiveDeviceDataProcFs();

private:
    QString m_zdmDevice;

    struct megazone_info *m_data;
    int m_wpf;
    int m_usedf;
    int m_statusf;
    int m_fd;
    int m_count;
    int m_zoom;
    uint64_t m_zone_total;

    bool m_playback;
    struct zdm_record *m_record;
};

#endif // _ZONESWIDGET_H_
