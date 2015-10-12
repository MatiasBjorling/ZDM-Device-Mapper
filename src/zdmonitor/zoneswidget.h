/**
 * ---------------------------------------------------------------------------------------------
 * Copyright (c) 2014 Honda R&D Americas, Inc.
 * All rights reserved.
 *
 * No person may copy, distribute, publicly display, create derivative
 * works from or otherwise use or modify this software without first obtaining a license
 * from Honda R&D Americas, Inc.
 *
 * To obtain a license, contact hsvl@hra.com
 * ---------------------------------------------------------------------------------------------
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


// request an info dump from ZDM:
#define ZDM_IOC_MZCOUNT          0x5a4e0001
#define ZDM_IOC_WPS              0x5a4e0002
#define ZDM_IOC_FREE             0x5a4e0003
#define ZDM_IOC_STATUS           0x5a4e0004

#define Z_WP_GC_FULL            (1u << 31)
#define Z_WP_GC_ACTIVE          (1u << 30)
#define Z_WP_GC_TARGET          (1u << 29)
#define Z_WP_GC_READY           (1u << 28)
#define Z_WP_NON_SEQ            (1u << 27)


/**
 */
struct zdm_ioc_status {
	uint64_t b_used;
	uint64_t b_available;
	uint64_t b_discard;
	uint64_t m_used;
	uint64_t mc_entries;
	uint64_t mlut_blocks;
	uint64_t crc_blocks;
	uint64_t inpool;
	uint32_t bins[40];
};

/**
 */
struct zdm_ioc_request {
    uint32_t result_size;
    uint32_t megazone_nr;
};

/**
 */
union zdm_ioc_state {
	struct zdm_ioc_request request;
	struct zdm_ioc_status  status;
};

/**
 */
struct megazone_info {
        uint32_t wps[1024];
        uint32_t free[1024];
        union zdm_ioc_state state;
};

/**
 */
class ZonesWidget : public QWidget
{
    Q_OBJECT
public:
    ZonesWidget(QWidget *parent=0);

    int setDevice(QString zdmDevice);
    int updateView(int zoom);
    int getMZCount(void)
    {
	return m_count;
    }
    struct megazone_info * getMZData(void)
    {
	return m_data;
    }
    

    virtual QSize sizeHint();
    virtual QSize minimumSizeHint();

protected:
    virtual void resizeEvent(QResizeEvent *event);
    virtual void paintEvent(QPaintEvent *e);
    void doPaint(QPaintEvent *e);
    void doDrawZones(QPainter& painter, QRect& area);

private:
    QString m_zdmDevice;

    struct megazone_info *m_data;
    int m_fd;
    int m_count;
    int m_zoom;
    uint64_t m_zone_total;
};

#endif // _ZONESWIDGET_H_
