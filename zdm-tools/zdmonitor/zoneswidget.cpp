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

#include <QPainter>
#include <QList>
#include <QDebug>
#include <QDir>
#include <cmath>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utypes.h>

#include <libcrc.h>

#include "zoneswidget.h"

ZonesWidget::ZonesWidget(QWidget *parent)
    : QWidget(parent),
      m_data(0),
      m_fd(-1),
      m_count(0),
      m_zoom(-1),
      m_zone_total(0ul),
      m_playback(false),
      m_record(NULL)
{
}

int ZonesWidget::getMZCount(void)
{
    return m_count;
}

struct megazone_info * ZonesWidget::getMZData(void)
{
    struct megazone_info * draw = m_data;

    if (!draw && m_record)
    {
        draw = m_record->data;
    }
    return draw;
}

int ZonesWidget::openProcWpEntry(QString zdmDevice)
{
    int rcode = 0;
    QString procPath;
    procPath.sprintf("/proc/%ls/" PROC_WP, (wchar_t*)zdmDevice.utf16());
    QByteArray ba = procPath.toLocal8Bit();
    const char *device = ba.data();

    m_wpf = ::open(device, O_RDONLY);
    if (m_wpf != -1)
    {
        rcode = 1;
    }

    return rcode;
}

int ZonesWidget::openProcUsedEntry(QString zdmDevice)
{
    int rcode = 0;
    QString procPath;
    procPath.sprintf("/proc/%ls/" PROC_FREE, (wchar_t*)zdmDevice.utf16());
    QByteArray ba = procPath.toLocal8Bit();
    const char *device = ba.data();

    m_usedf = ::open(device, O_RDONLY);
    if (m_usedf != -1)
    {
        rcode = 1;
    }

    return rcode;
}

int ZonesWidget::openProcStatusEntry(QString zdmDevice)
{
    int rcode = 0;
    QString procPath;
    procPath.sprintf("/proc/%ls/" PROC_DATA, (wchar_t*)zdmDevice.utf16());
    QByteArray ba = procPath.toLocal8Bit();
    const char *device = ba.data();

    m_statusf = ::open(device, O_RDONLY);
    if (m_statusf != -1)
    {
        rcode = 1;
    }

    return rcode;
}

int ZonesWidget::setDevice(QString zdmDevice)
{
    int rcode = -1;
    QString procPath;

    /* close any active file/device */
    if (m_fd != -1)
    {
        ::close(m_fd);
        m_fd = -1;
        m_count = 0;
        m_zone_total = 0ul;
    }

    if (m_data)
    {
        delete[] m_data;
    }
    if (m_record)
    {
        free(m_record);
    }
    m_data = NULL;
    m_record = NULL;

    if (m_wpf)
    {
        ::close(m_wpf);
    }
    if (m_usedf)
    {
        ::close(m_usedf);
    }
    if (m_statusf)
    {
        ::close(m_statusf);
    }

    /* see if the user is asking for a /proc/zdm_* entry */
    procPath.sprintf("/proc/%ls", (wchar_t*)zdmDevice.utf16());
    QDir folder(procPath);

    if (folder.exists())
    {
        /* take the new path */
        if (openProcWpEntry(zdmDevice) &&
                openProcUsedEntry(zdmDevice) &&
                openProcStatusEntry(zdmDevice) )
        {
            rcode = 0;
            m_zdmDevice = zdmDevice;
        }
    }
    else
    {
        /* follow the old path, or playback file */
        QByteArray ba = zdmDevice.toLocal8Bit();
        const char *device = ba.data();

        struct stat m;

        m_fd = ::open(device, O_RDWR);
        m_zdmDevice = zdmDevice;
        ::fstat(m_fd, &m);
        m_playback = S_ISREG(m.st_mode) ? true : false;
        rcode = m_fd;
    }
    return rcode;
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

int ZonesWidget::updatePlaybackView()
{
    int err = 0;
    int64_t recsz;
    off_t pos = lseek(m_fd, 0, SEEK_CUR);
    uint32_t crc = 0;

    if (!m_record)
    {
        struct zdm_record header;

        int bytes = ::read(m_fd, &header, sizeof(header));
        if (bytes != sizeof(header))
        {
            err = -1;
            goto out;
        }
        recsz = header.size;

        if (recsz > 0)
        {
            qDebug("Size: %ld", recsz);
            m_record = static_cast<struct zdm_record *>(malloc(recsz));
            if (!m_record)
            {
                err = -1;
                goto out;
            }
        }

        lseek(m_fd, pos, SEEK_SET);
        m_record->size = recsz;
    }

    recsz = m_record->size;
    qDebug("Read Size: %ld", recsz);

    if (recsz != ::read(m_fd, m_record, recsz))
    {
        err = -1;
        goto out;
    }

    crc = m_record->crc32;
    m_record->crc32 = 0u;
    m_record->crc32 = crc32c(~0u, m_record, m_record->size);

    qDebug("CRC: %08x vs calc: %08x", crc, m_record->crc32);


    /* bail on corrupt records (for now) */
    if (crc != m_record->crc32 || recsz != m_record->size)
    {
        free(m_record);
        m_record = NULL;

        qDebug("Corrupt entry (bad CRC or record size)");

        lseek(m_fd, pos, SEEK_SET);
        err = -1;
        goto out;
    }

    if (0ul == m_zone_total)
    {
        int last = m_record->mz_count - 1;

        m_zone_total = last * 1024ul;
        for (int entry = 0; entry < 1024; entry++)
        {
            uint32_t wp = m_record->data[last].wps[entry];
            if (~0u == wp)
            {
                m_zone_total += entry;
                break;
            }
        }
    }
    m_count = m_record->mz_count;

    qDebug("MZ count: %d - total zones: %" PRIu64,
           m_count, m_zone_total );

out:
    return err;
}

int ZonesWidget::updateFakeDemoView()
{
    int err = -1;

#if 1
    qDebug("ERROR: Displaying FakeDemo Display");
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
            if (entry & 1)
            {
                m_data[entry].wps[val] = 0x10000 - (val * 64);
            }
            m_data[entry].free[val] = 0x10000 - m_data[entry].wps[val];
            if (entry & 1)
            {
                m_data[entry].wps[val] |= 0x80 << 24;
            }
            else
            {
                m_data[entry].wps[val] |= (val & 0xf8) << 24;
            }
        }
    }
    m_data[2].wps[255] = ~0u;
    m_data[2].wps[256] = ~0u;
    m_data[2].wps[257] = ~0u;

    m_zone_total = (1024 * m_count) - 768;
    err = 0;
#endif

    return err;
}

#if 0
/*
 *  Get data from /proc entries *OR* from ioctl calls (pre 4.4 kernel)
 */
int ZonesWidget::getLiveDeviceDataIoctl()
{
    int err = -1;
    int rcode = ioctl(m_fd, ZDM_IOC_MZCOUNT, 0);

    if (rcode > 0)
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
                break;
            }
            rcode = ioctl(m_fd, ZDM_IOC_FREE, req_free);
            if (rcode < 0)
            {
                printf("ERROR: %d\n", rcode);
                break;
            }
            rcode = ioctl(m_fd, ZDM_IOC_STATUS, req_status);
            if (rcode < 0)
            {
                qDebug("ERROR: ZDM_IOC_STATUS -> %d", rcode);
                break;
            }
        }

        err = rcode;

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
    return err;
}
#endif // Removed at 4.4

struct zone_value_entry
{
    u32 zone;
    u32 value;
};

int ZonesWidget::getLiveDeviceDataProcFs()
{
    int err = 0;
    QList<u32> used;
    QList<u32> wp;
    struct zone_value_entry entry;
    struct zdm_ioc_status  status;
    ssize_t in;
    off_t pos = 0ul;
    int no;

    do
    {
        in = read(m_usedf, &entry, sizeof(entry));
        if (in == sizeof(entry))
        {
            used.append(entry.value);
        }
    }
    while (in > 0);

    if (in < 0)
    {
        err--;
    }

    do
    {
        in = read(m_wpf, &entry, sizeof(entry));
        if (in == sizeof(entry))
        {
            wp.append(entry.value);
        }
    }
    while (in > 0);

    if (in < 0)
    {
        err--;
    }

    in = read(m_statusf, &status, sizeof(status));
    if (in != sizeof(status))
    {
        err--;
    }

    lseek(m_usedf,   pos, SEEK_SET);
    lseek(m_wpf,     pos, SEEK_SET);
    lseek(m_statusf, pos, SEEK_SET);

    if (err == 0 && used.count() != m_zone_total)
    {
        if (m_data)
        {
            delete[] m_data;
            m_data = NULL;
        }
        else
        {
            qDebug("New total: %d", used.count());
        }
        m_zone_total = used.count();
        m_count = (m_zone_total + 1023) / 1024;
        qDebug("MZ count %d, total zones: %" PRIu64,
               m_count, m_zone_total );
    }

    if (err == 0 && m_zone_total > 0)
    {
        if (!m_data)
        {
            m_data = new struct megazone_info[m_count];
        }
        if (m_data)
        {
            int mz = 0;
            int dzoff = 0;

            for (int entry = 0; entry < used.count(); entry++)
            {
                mz = entry / 1024;
                dzoff = entry % 1024;

                m_data[mz].wps[dzoff]  = wp[entry];
                m_data[mz].free[dzoff] = used[entry];
                memcpy(&m_data[mz].state.status, &status, sizeof(status));
            }
        }
    }
    return err;
}


int ZonesWidget::updateLiveDeviceView()
{
    int err;

    if (m_fd != -1)
    {
        err = -1; // getLiveDeviceDataIoctl();
    }
    else
    {
        err = getLiveDeviceDataProcFs();
    }
    return err;
}

int ZonesWidget::updateView(int zoom)
{
    int err = 0;
    int rcode = -1;

    m_zoom = zoom;

    if (m_fd == -1 && m_wpf == -1)
    {
        err = updateFakeDemoView();
    }
    else if (m_playback)
    {
        err = updatePlaybackView();
    }
    else
    {
        err = updateLiveDeviceView();
    }

    if (!err)
    {
        this->update();
    }
    return rcode;
}

void ZonesWidget::doDrawZones(QPainter& painter, QRect& area)
{
    QColor recalc    (0x1f, 0x4f, 0x8f);
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

    int entry = 0; // (0 == mzone) ? 1 : 0;

    struct megazone_info * draw = getMZData();

    for (int row = 2; row < height && mzone < last_mzone; row += row_h)
    {
        for (int col = 0; col < columns; col++)
        {
            if (entry >= 1024)
            {
                mzone++;
                entry %= 1024;
                break; /* go to next row */
            }
            if (mzone < last_mzone)
            {
                uint32_t wp = draw[mzone].wps[entry];
                uint32_t fr = draw[mzone].free[entry] & 0xFFFFFF;

                if (~0u == wp)
                {
                    break;
                }

                if       ( Z_WP_GC_FULL & wp )
                {
                    usage = gc_full;
                }
                else if  ( Z_WP_GC_ACTIVE & wp )
                {
                    usage = gc_active;
                }
                else if  ( Z_WP_GC_TARGET & wp )
                {
                    usage = gc_target;
                }
                else if  ( Z_WP_GC_READY & wp )
                {
                    usage = gc_ready;
                }
                else if  ( Z_WP_NON_SEQ & wp )
                {
                    usage = non_seq;
                }
                else if  ( Z_WP_RESV_01 & wp ) /* RECALC */
                {
                    usage = recalc;
                }
                else if  ( Z_WP_RESV_02 & wp )
                {
                    usage = gc_ready;
                }
                else if  ( Z_WP_RESV_03 & wp )
                {
                    usage = gc_ready;
                }
                else
                {
                    usage = non_flag;
                }

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
