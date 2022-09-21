#include "GTGUIQT.h"
#include <QtWidgets/QApplication>
#include <QSplitter>
#include <QTextEdit>
#include <qlistwidget.h>
#include <qgridlayout.h>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    GTGUIQT w;
    w.show();
    return a.exec();
}
