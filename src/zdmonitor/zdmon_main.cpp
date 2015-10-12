#include "zdmon.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QStringList args = a.arguments();
    ZDMon w;
    w.args(args);
    w.show();

    return a.exec();
}
