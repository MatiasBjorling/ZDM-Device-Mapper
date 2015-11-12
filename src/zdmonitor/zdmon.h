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

#ifndef ZDMON_H
#define ZDMON_H

#include <QMainWindow>
#include <QTimer>

namespace Ui {
class ZDMon;
}

class ZDMon : public QMainWindow
{
    Q_OBJECT

public:
    explicit ZDMon(QWidget *parent = 0);
    ~ZDMon();

    void args(QStringList args);

private slots:
    void onClockUpdate();
    void onRefreshUpdate(int);

private:
    QTimer     mClockUpdate;
    Ui::ZDMon *ui;
};

#endif // ZDMON_H
