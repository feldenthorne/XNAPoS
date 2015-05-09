// Copyright (c) 2011-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "splashscreen.h"
#include "clientversion.h"
#include "util.h"

#include <QPainter>
#include <QApplication>

SplashScreen::SplashScreen(const QPixmap &pixmap, Qt::WindowFlags f) :
    QSplashScreen(pixmap, f)
{
    setAutoFillBackground(true);

    // set reference point, paddings
    int paddingRight            = 420;
    int paddingTop              = 290;
    int titleVersionVSpace      = 17;
    int titleCopyrightVSpace    = 40;
    int line                    = 18;

    float fontFactor            = 1.0;

    // define text to place
    QString titleText        = tr("DeOxyRibose Core");
    QString versionText      = QString("Version %1").arg(QString::fromStdString(FormatFullVersion()));
    QString copyrightText1   = QChar(0xA9)+QString(" 2009-%1 ").arg(COPYRIGHT_YEAR) + QString(tr("Bitcoin Developers"));
    QString copyrightText2   = QChar(0xA9)+QString(" 2012-%1 ").arg(COPYRIGHT_YEAR) + QString(tr("PPCoin Developers"));
    QString copyrightText3   = QChar(0xA9)+QString(" 2014-%1 ").arg(COPYRIGHT_YEAR) + QString(tr("DeOxyRibose Developers"));
    QString testnetAddText   = QString(tr("[testnet]")); // define text to place as single text object

    // Create a painter path to make an outline of the text
    QPainterPath pixPath;

    QString font             = "Verdana";

    // load the bitmap for writing some text over it
    QPixmap newPixmap;
    if(GetBoolArg("-testnet")) {
        newPixmap     = QPixmap(":/images/splash_testnet");
    }
    else {
        newPixmap     = QPixmap(":/images/splash");
    }

    QPainter pixPaint(&newPixmap);
    QPen pen;
    pen.setColor(QColor(0,0,0,255));
    pen.setWidthF(2.5);
    pixPaint.setRenderHint(QPainter::Antialiasing, true);
    pixPaint.setPen(pen);

    // check font size and drawing with
    pixPaint.setFont(QFont(font, 20*fontFactor));
    QFontMetrics fm = pixPaint.fontMetrics();
    int titleTextWidth  = fm.width(titleText);
    if(titleTextWidth > 200) {
        // strange font rendering, Arial probably not found
        fontFactor = 0.75;
        pixPaint.setFont(QFont(font, 20*fontFactor));
    }

    fm = pixPaint.fontMetrics();
    titleTextWidth  = fm.width(titleText);
    pixPath.addText(newPixmap.width()-titleTextWidth-paddingRight,paddingTop,font,titleText);

    pixPaint.setFont(QFont(font, 14*fontFactor));

    // if the version string is too long, reduce size
    fm = pixPaint.fontMetrics();
    int versionTextWidth  = fm.width(versionText);
    if(versionTextWidth > titleTextWidth+paddingRight-10) {
        pixPaint.setFont(QFont(font, 6*fontFactor));
        titleVersionVSpace -= 5;
    }
    pixPath.addText(newPixmap.width()-titleTextWidth-paddingRight+2,paddingTop+titleVersionVSpace,font,versionText);

    // draw copyright stuff
    pixPath.addText(newPixmap.width()-titleTextWidth-paddingRight,paddingTop+titleCopyrightVSpace,font,copyrightText1);
    pixPath.addText(newPixmap.width()-titleTextWidth-paddingRight,paddingTop+titleCopyrightVSpace+line,font,copyrightText2);
    pixPath.addText(newPixmap.width()-titleTextWidth-paddingRight,paddingTop+titleCopyrightVSpace+(2*line),font,copyrightText3);

    // draw testnet string if testnet is on
    if(GetBoolArg("-testnet")) {
        QFont boldFont = QFont(font, 10*fontFactor);
        boldFont.setWeight(QFont::Bold);
        pixPaint.setFont(boldFont);
        fm = pixPaint.fontMetrics();
        int testnetAddTextWidth  = fm.width(testnetAddText);
        pixPath.addText(newPixmap.width()-testnetAddTextWidth-10,15,font,testnetAddText);
    }  

    // Draw the text outline, then re-set the brush and pen to draw the text
    pixPaint.drawPath(pixPath);
    pixPaint.setBrush(QBrush(QColor(255,255,255,255), Qt::SolidPattern));
    pen.setWidthF(0.1);
    pen.setColor(QColor(255,255,255,255));
    pixPaint.setPen(pen);
    pixPaint.drawPath(pixPath);

    pixPaint.end();

    this->setPixmap(newPixmap);
}
