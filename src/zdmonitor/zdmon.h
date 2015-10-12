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
