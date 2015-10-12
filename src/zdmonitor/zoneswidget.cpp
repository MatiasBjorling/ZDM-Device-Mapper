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

#include <QPainter>
#include <QList>
#include <QDebug>
#include <cmath>

#include "zoneswidget.h"

ZonesWidget::ZonesWidget(QWidget *parent)
 : QWidget(parent),
   m_data(0),
   m_fd(-1),
   m_count(0),
   m_zoom(-1),
   m_zone_total(0ul)
{
}

int ZonesWidget::setDevice(QString zdmDevice)
{
    QByteArray ba = zdmDevice.toLocal8Bit();
    const char *device = ba.data();

    if (m_fd != -1)
    {
        ::close(m_fd);
        m_fd = -1;
        m_count = 0;
        m_zone_total = 0ul;
        if (m_data) {
            delete[] m_data;
        }
    }
    m_fd = ::open(device, O_RDWR);
    m_zdmDevice = zdmDevice;

    return m_fd;
}

QSize ZonesWidget::sizeHint()
{
    return QSize(6400,8000);
}

QSize ZonesWidget::minimumSizeHint()
{
    return QSize(6400,8000);
}

void ZonesWidget::resizeEvent(QResizeEvent * event)
{
    (void) event;
}

int ZonesWidget::updateView(int zoom)
{
    int err = 0;
    int rcode = -1;

    m_zoom = zoom;
    if (m_fd != -1)
    {
        rcode = ioctl(m_fd, ZDM_IOC_MZCOUNT, 0);
    }

    if (rcode < 1)
    {
        qDebug("ERROR: ZDM_IOC_MZCOUNT -> %d [fd:%d]", rcode, m_fd);
        err = -1;
#if 1
        m_count = 3;
        if (!m_data)
        {
            m_data = new struct megazone_info[m_count];
            memset(m_data, 0, sizeof(megazone_info) * m_count);
        }

        for (int entry = 0; entry < m_count; entry++)
        {
            for (uint32_t val = 0; val < 1024; val++)
            {
                m_data[entry].wps[val] = val * 64;
                if (entry & 1) m_data[entry].wps[val] = 0x10000 - (val * 64);
                m_data[entry].free[val] = 0x10000 - m_data[entry].wps[val];
                if (entry & 1)
                    m_data[entry].wps[val] |= 0x80 << 24;
                else
                    m_data[entry].wps[val] |= (val & 0xf8) << 24;
            }
        }
        m_data[2].wps[255] = ~0u;
        m_data[2].wps[256] = ~0u;
        m_data[2].wps[257] = ~0u;

        m_zone_total = (1024 * m_count) - 768;
        err = 0;
#endif
    }
    else
    {
        m_count = rcode;

        if (!m_data)
        {
            m_data = new struct megazone_info[m_count];
        }

        for (int entry = 0; entry < m_count; entry++)
        {
            struct zdm_ioc_request * req_wps  = (struct zdm_ioc_request *)m_data[entry].wps;
            struct zdm_ioc_request * req_free = (struct zdm_ioc_request *)m_data[entry].free;
            union zdm_ioc_state * req_status  = (union zdm_ioc_state *)&m_data[entry].state;

            req_wps->result_size = sizeof(m_data[entry].wps);
            req_wps->megazone_nr = entry;
            req_free->result_size = sizeof(m_data[entry].free);
            req_free->megazone_nr = entry;
            req_status->request.result_size = sizeof(m_data[entry].state);
            req_status->request.megazone_nr = entry;

            rcode = ioctl(m_fd, ZDM_IOC_WPS, req_wps);
            if (rcode < 0)
            {
                qDebug("ERROR: ZDM_IOC_WPS -> %d", rcode);
                err = -1;
                break;
            }
            rcode = ioctl(m_fd, ZDM_IOC_FREE, req_free);
            if (rcode < 0)
            {
                printf("ERROR: %d\n", rcode);
                err = -1;
                break;
            }
            rcode = ioctl(m_fd, ZDM_IOC_STATUS, req_status);
            if (rcode < 0)
            {
                qDebug("ERROR: ZDM_IOC_STATUS -> %d", rcode);
                err = -1;
                break;
            }
        }

        if (0ul == m_zone_total)
        {
            int last = m_count - 1;

            m_zone_total = last * 1024ul;
            for (int entry = 0; entry < 1024; entry++)
            {
                uint32_t wp = m_data[last].wps[entry];
                if (~0u == wp)
                {
                    m_zone_total += entry;
                    break;
                }
            }
            qDebug("MZ count: %d - total zones: %" PRIu64,
                   m_count, m_zone_total );
        }
    }
    if (!err)
    {
        this->update();
    }
    return rcode;
}

void ZonesWidget::doDrawZones(QPainter& painter, QRect& area)
{
    QColor gc_ready  (0x1f, 0x4f, 0x8f);
    QColor gc_target (0x1f, 0xcf, 0x00);
    QColor gc_active (0x00, 0xcf, 0xff);
    QColor gc_full   (0x1f, 0x00, 0xff);
    QColor non_seq   (0xff, 0x00, 0xff);
    QColor non_flag  (0xff, 0xff, 0x00);
    QColor stale     (0x77, 0x77, 0x77);
    QColor usage;
    int width  = area.width() - 4;
    int height = area.height() - 4;
    uint64_t pixels = (width * height) / 3;
    uint64_t zones = m_zone_total;
    int mzone  = 0;
    int row_h = 12;
    int last_mzone = m_count;

    if (m_zoom != -1)
    {
        zones = 1024;
        if (m_zoom == (m_count - 1))
        {
            zones = m_zone_total - ((m_count - 1) * 1024);
        }
        mzone = m_zoom;
        last_mzone = mzone + 1;
    }

    uint64_t c_max = pixels / zones;
    if (c_max < 1ul)
    {
        c_max = 1ul;
    }
    if (c_max > 64ul)
    {
        c_max = 64ul;
    }

    int columns = width / c_max;
    int h_needed = zones / columns;

//    qDebug("MZ count: %d - total zones: %" PRIu64, m_count, m_zone_total );
//    qDebug("pixels: %" PRIu64 ", mzone: %d, last_mzone: %d, zones %" PRIu64, pixels, mzone, last_mzone, zones );

    if (height > h_needed)
    {
        row_h = height / h_needed;
        if (row_h < 3)
        {
            row_h = 3;
        }
    }
//    qDebug("c_max: %" PRIu64 ", columns: %d, h_needed: %d, row_h: %d", c_max, columns, h_needed, row_h );

    int entry = (0 == mzone) ? 1 : 0;

    for (int row = 2; row < height && mzone < last_mzone; row += row_h)
    {
        for (int col = 0; col < columns; col++)
        {
            if (entry >= 1024) {
                mzone++;
                entry %= 1024;
                break; /* go to next row */
            }
            if (mzone < last_mzone)
            {
                uint32_t wp = m_data[mzone].wps[entry];
                uint32_t fr = m_data[mzone].free[entry];

                if (~0u == wp)
                {
                    break;
                }

                if       ( Z_WP_GC_FULL & wp )   usage = gc_full;
                else if  ( Z_WP_GC_ACTIVE & wp ) usage = gc_active;
                else if  ( Z_WP_GC_TARGET & wp ) usage = gc_target;
                else if  ( Z_WP_GC_READY & wp )  usage = gc_ready;
                else if  ( Z_WP_NON_SEQ & wp )   usage = non_seq;
                else                             usage = non_flag;

                wp &= 0xFFFFFF;
                int free_row = row + row_h - 1;

                QRect used ((col * 64) + 2, row,      wp / 1024, row_h);
                QRect avail((col * 64) + 2, free_row, fr / 1024, 1);
                painter.fillRect(used, usage);
                painter.fillRect(avail, stale);
            }
            entry++;
        }
    }
}

void ZonesWidget::doPaint(QPaintEvent *e)
{
    QPainter painter(this);
    QRect area = rect();
    QColor blk(0x0, 0x0, 0x0);
    painter.fillRect(area, blk);

    if (m_count > 0 && m_zone_total > 0)
    {
        doDrawZones(painter, area);
    }

    (void) e;
}

void ZonesWidget::paintEvent(QPaintEvent *e)
{
    doPaint(e);
}
