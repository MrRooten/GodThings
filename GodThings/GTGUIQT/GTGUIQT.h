#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_GTGUIQT.h"

class GTGUIQT : public QMainWindow
{
    Q_OBJECT

public:
    GTGUIQT(QWidget *parent = nullptr);
    ~GTGUIQT();

private:
    Ui::GTGUIQTClass ui;
};
