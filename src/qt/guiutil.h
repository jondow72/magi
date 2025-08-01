#ifndef GUIUTIL_H
#define GUIUTIL_H

#include <QString>
#include <QObject>
#include <QMessageBox>
#include <QLabel>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QStackedWidget>

QT_BEGIN_NAMESPACE
class QFont;
class QLineEdit;
class QWidget;
class QDateTime;
class QUrl;
class QAbstractItemView;
QT_END_NAMESPACE
class SendCoinsRecipient;

/** Utility functions used by the Bitcoin Qt UI.
 */
namespace GUIUtil
{
    // Create human-readable string from date
    QString dateTimeStr(const QDateTime &datetime);
    QString dateTimeStr(qint64 nTime);

    // Render Bitcoin addresses in monospace font
    QFont bitcoinAddressFont();

    // Set up widgets for address and amounts
    void setupAddressWidget(QLineEdit *widget, QWidget *parent);
    void setupAmountWidget(QLineEdit *widget, QWidget *parent);

    // Parse "bitcoin:" URI into recipient object, return true on successful parsing
    // See Bitcoin URI definition discussion here: https://bitcointalk.org/index.php?topic=33490.0
    bool parseBitcoinURI(const QUrl &uri, SendCoinsRecipient *out);
    bool parseBitcoinURI(QString uri, SendCoinsRecipient *out);

    // HTML escaping for rich text controls
    QString HtmlEscape(const QString& str, bool fMultiLine=false);
    QString HtmlEscape(const std::string& str, bool fMultiLine=false);

    /** Copy a field of the currently selected entry of a view to the clipboard. Does nothing if nothing
        is selected.
       @param[in] column  Data column to extract from the model
       @param[in] role    Data role to extract from the model
       @see  TransactionView::copyLabel, TransactionView::copyAmount, TransactionView::copyAddress
     */
    void copyEntryData(QAbstractItemView *view, int column, int role=Qt::EditRole);

    /** Get save filename, mimics QFileDialog::getSaveFileName, except that it appends a default suffix
        when no suffix is provided by the user.

      @param[in] parent  Parent window (or 0)
      @param[in] caption Window caption (or empty, for default)
      @param[in] dir     Starting directory (or empty, to default to documents directory)
      @param[in] filter  Filter specification such as "Comma Separated Files (*.csv)"
      @param[out] selectedSuffixOut  Pointer to return the suffix (file type) that was selected (or 0).
                  Can be useful when choosing the save file format based on suffix.
     */
    QString getSaveFileName(QWidget *parent=0, const QString &caption=QString(),
                                   const QString &dir=QString(), const QString &filter=QString(),
                                   QString *selectedSuffixOut=0);

    /** Get connection type to call object slot in GUI thread with invokeMethod. The call will be blocking.

       @returns If called from the GUI thread, return a Qt::DirectConnection.
                If called from another thread, return a Qt::BlockingQueuedConnection.
    */
    Qt::ConnectionType blockingGUIThreadConnection();

    // Determine whether a widget is hidden behind other windows
    bool isObscured(QWidget *w);

    // Open debug.log
    void openDebugLogfile();

    // Open config file
    void openConfigfile();

    /** Qt event filter that intercepts ToolTipChange events, and replaces the tooltip with a rich text
      representation if needed. This assures that Qt can word-wrap long tooltip messages.
      Tooltips longer than the provided size threshold (in characters) are wrapped.
     */
    class ToolTipToRichTextFilter : public QObject
    {
        Q_OBJECT

    public:
        explicit ToolTipToRichTextFilter(int size_threshold, QObject *parent = 0);

    protected:
        bool eventFilter(QObject *obj, QEvent *evt);

    private:
        int size_threshold;
    };

    bool GetStartOnSystemStartup();
    bool SetStartOnSystemStartup(bool fAutoStart);

    /** Save window size and position */
    void saveWindowGeometry(const QString& strSetting, QWidget *parent);
    /** Restore window size and position */
    void restoreWindowGeometry(const QString& strSetting, const QSize &defaultSizeIn, QWidget *parent);

    /** Help message for Bitcoin-Qt, shown with --help. */
    class HelpMessageBox : public QMessageBox
    {
        Q_OBJECT

    public:
        HelpMessageBox(QWidget *parent = 0);

        /** Show message box or print help message to standard output, based on operating system. */
        void showOrPrint();

        /** Print help message to console */
        void printToConsole();

    private:
        QString header;
        QString coreOptions;
        QString uiOptions;
    };
    /* Convert seconds into a QString with days, hours, mins, secs */
    QString formatDurationStr(int secs);

    class QCLabel : public QLabel
    {
        Q_OBJECT

    public:
        QCLabel(const QString& text="", QWidget* parent=0);
        ~QCLabel(){};

    signals:
        void clicked();

    protected:
        void mouseReleaseEvent(QMouseEvent* event);
    };


    class QPriceInfo : public QObject
    {
        Q_OBJECT

    public:
        QPriceInfo();
        ~QPriceInfo(){};
        void checkPrice();
        double getPriceInBTC()
        {
            return rPriceInBTC;
        }

        double getPriceInUSD()
        {
            return rPriceInUSD;
        }

    signals:
        void finished();

    private:
        QUrl BTCPriceCheckURL;
        QUrl MagiToUSDPriceCheckURL;
        double rPriceInBTC;
        double rPriceInUSD;
        QNetworkAccessManager mCheckUSDPrice;
        QNetworkAccessManager mCheckBTCPrice;
    private slots:
        void updatePriceInUSD(QNetworkReply* resp);
        void updatePriceInBTC(QNetworkReply* resp);
    };

    class QRStackedWidget : public QStackedWidget
    {
        Q_OBJECT
    public:
        QRStackedWidget(QWidget *parent = 0) : QStackedWidget(parent) {};
        ~QRStackedWidget(){};
        void addWidget(QWidget* pWidget);
        void onCurrentChanged(int index);
    };


} // namespace GUIUtil

#endif // GUIUTIL_H
