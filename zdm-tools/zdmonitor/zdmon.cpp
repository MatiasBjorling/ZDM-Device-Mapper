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

#include "zdmon.h"
#include "ui_zdmon.h"
#include "zoneswidget.h"

#include <QDebug>

// ---------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------
ZDMon::ZDMon(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::ZDMon)
{
    int refresh = 1000;

    ui->setupUi(this);
    connect(&mClockUpdate,   SIGNAL(timeout()), this, SLOT(onClockUpdate()));
    connect(ui->spinRefresh, SIGNAL(valueChanged(int)), this, SLOT(onRefreshUpdate(int)));

    refresh = ui->spinRefresh->value() * 1000;
    mClockUpdate.start(refresh);
}

// ---------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------
ZDMon::~ZDMon()
{
    delete ui;
}

// ---------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------
void ZDMon::onRefreshUpdate(int value)
{
    int refresh = value * 1000;
    mClockUpdate.stop();
    mClockUpdate.start(refresh);
}

// ---------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------
void ZDMon::onClockUpdate()
{
    int zoom = ui->spinZoom->value();
    int count = ui->zones->getMZCount();

    ui->zones->updateView(zoom);
    ui->spinZoom->setMaximum(count - 1);
    if (count > 0)
    {
        struct megazone_info * data = ui->zones->getMZData();
        uint64_t ram = 0;
        uint64_t used = 0;
        uint64_t avail = 0;
        uint64_t stale = 0;

        ram = data[0].state.status.inpool;
        for (int mznr = 0; mznr < count; mznr++)
        {
            used  += data[mznr].state.status.b_used;
            avail += data[mznr].state.status.b_available;
            stale += data[mznr].state.status.b_discard;
        }

        QString tRam;
        QString tUsed;
        QString tAvail;
        QString tStale;

        tRam.sprintf("%'"   PRIu64, ram);
        tUsed.sprintf("%'"  PRIu64, used);
        tAvail.sprintf("%'" PRIu64, avail);
        tStale.sprintf("%'" PRIu64, stale);

        ui->lRam->setText(tRam);
        ui->lFree->setText(tAvail);
        ui->lStale->setText(tStale);
        ui->lUsed->setText(tUsed);

        if (-1 < zoom && zoom < count)
        {
             tUsed.sprintf("%'"  PRIu64, data[zoom].state.status.b_used);
             tAvail.sprintf("%'" PRIu64, data[zoom].state.status.b_available);
             tStale.sprintf("%'" PRIu64, data[zoom].state.status.b_discard);

             ui->mzFree->setText(tAvail);
             ui->mzStale->setText(tStale);
             ui->mzUsed->setText(tUsed);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------
void ZDMon::args(QStringList args)
{
    qDebug() << args;

    int argc;
    for (argc = 1; argc < args.count(); argc++)
    {
        QString arg = args[argc];
        if (arg.startsWith("-")) {
            qDebug() << "No parsing options " << arg << " .. yet?";
        } else {
            qDebug() << "Trying to open " << arg << " as a ZDM instance." << arg;
            if (arg.startsWith("/proc/")) {
                arg = arg.mid(6);
            }
            int fd = ui->zones->setDevice(arg);
            if (fd != -1) {
                QString title;
                title.sprintf("ZDMon - %ls", (wchar_t*)arg.utf16());
                setWindowTitle(title);
            }
        }
    }
}


