#include <QApplication>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QPushButton>
#include <QTableWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QLabel>
#include <QGroupBox>
#include <QProgressBar>
#include <QStatusBar>
#include <QSplitter>
#include <QTimer>
#include <QMessageBox>
#include <QComboBox>
#include <QSpinBox>
#include <QHeaderView>
#include <QThread>
#include <QMutex>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QInputDialog>
#include <QFileDialog>
#include <QJsonArray>
#include <QProcess>
#include <QDialog>
#include <QTextStream>
#include <QDebug>
#include <QRegularExpression>

// Platform-specific includes
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
    
    // Npcap/WinPcap includes
    #include <pcap.h>
    #pragma comment(lib, "wpcap.lib")
    #pragma comment(lib, "Packet.lib")
#else
    #include <ifaddrs.h>
    #include <netdb.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <pcap/pcap.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <sys/select.h>
#endif

// Packet structure for our application
struct PacketInfo {
    int id;
    QDateTime timestamp;
    QString sourceIP;
    QString destinationIP;
    QString protocol;
    int sourcePort;
    int destinationPort;
    int length;
    QString summary;
    QByteArray rawData;
    
    PacketInfo() : id(0), sourcePort(0), destinationPort(0), length(0) {}
};

// Forward declarations
class PacketAnalyzer;
class PacketCaptureWorker;

// Worker thread for packet capture
class PacketCaptureWorker : public QThread {
    Q_OBJECT
    
public:
    PacketCaptureWorker(const QString &interface, QObject *parent = nullptr)
        : QThread(parent), m_interface(interface), m_shouldStop(false) {}
    
    void stop() { m_shouldStop = true; }
    
signals:
    void packetCaptured(const PacketInfo &packet);
    void errorOccurred(const QString &error);
    
protected:
    void run() override;
    
private:
    QString m_interface;
    bool m_shouldStop;
};

// Main packet analyzer class
class PacketAnalyzer : public QObject {
    Q_OBJECT
    
public:
    PacketAnalyzer(QObject *parent = nullptr);
    ~PacketAnalyzer();
    
    bool startCapture(const QString &interface = "");
    void stopCapture();
    bool isCapturing() const { return m_isCapturing; }
    QStringList getNetworkInterfaces();
    
signals:
    void packetCaptured(const PacketInfo &packet);
    void errorOccurred(const QString &error);
    
private:
    PacketCaptureWorker *m_worker;
    bool m_isCapturing;
};

// Main window class
class MainWindow : public QMainWindow {
    Q_OBJECT
    
public:
    MainWindow(QWidget *parent = nullptr);
    
private slots:
    void startCapture();
    void stopCapture();
    void clearPackets();
    void scanNetwork();
    void sendTestPacket();
    void savePackets();
    void onPacketCaptured(const PacketInfo &packet);
    void onPacketTableSelectionChanged();
    
private:
    void setupUI();
    void setupLeftPanel(QWidget *parent);
    void setupRightPanel(QWidget *parent);
    void updateInterfaces();
    QString getSelectedInterface();
    void updatePacketCount();
    QString getDarkTheme();
    
    // Network utility functions
    QString getLocalIPAddress();
    bool pingHost(const QString &host);
    bool tcpPing(const QString &host, int port);
    QString getHostname(const QString &ip);
    bool sendTCPPacket(const QString &srcIP, const QString &dstIP, int port);
    void updateScanResults(const QStringList &devices, const QString &networkBase = "");
    bool isNmapAvailable();
    QStringList runNmapScan(const QString &networkRange);
    
    // UI Components
    QComboBox *m_interfaceCombo;
    QPushButton *m_startButton;
    QPushButton *m_stopButton;
    QPushButton *m_scanButton;
    QProgressBar *m_captureProgress;
    QLabel *m_statusLabel;
    QLabel *m_packetCountLabel;
    QTableWidget *m_packetTable;
    QTextEdit *m_packetDetails;
    
    // Core components
    PacketAnalyzer *m_analyzer;
    QMap<int, PacketInfo> m_packetData;
    
    // State
    bool m_isCapturing = false;
    int m_packetCount;
};

// Implementation of PacketCaptureWorker::run()
void PacketCaptureWorker::run() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    // Open the interface for packet capture
    handle = pcap_open_live(m_interface.toLocal8Bit().data(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        emit errorOccurred(QString("Couldn't open device: %1").arg(errbuf));
        return;
    }
    
    struct pcap_pkthdr header;
    const u_char *packet;
    int packetId = 0;
    
    while (!m_shouldStop) {
        packet = pcap_next(handle, &header);
        if (packet != nullptr) {
            PacketInfo info;
            info.id = ++packetId;
            info.timestamp = QDateTime::currentDateTime();
            info.length = header.len;
            info.rawData = QByteArray(reinterpret_cast<const char*>(packet), header.len);
            
            // Basic packet parsing
            if (header.len >= 14) { // Ethernet header
                const u_char *eth_header = packet;
                u_short eth_type = ntohs(*(u_short*)(eth_header + 12));
                
                if (eth_type == 0x0800 && header.len >= 34) { // IPv4
                    const u_char *ip_header = packet + 14;
                    info.sourceIP = QString("%1.%2.%3.%4")
                        .arg(ip_header[12]).arg(ip_header[13])
                        .arg(ip_header[14]).arg(ip_header[15]);
                    info.destinationIP = QString("%1.%2.%3.%4")
                        .arg(ip_header[16]).arg(ip_header[17])
                        .arg(ip_header[18]).arg(ip_header[19]);
                    
                    u_char protocol = ip_header[9];
                    switch (protocol) {
                        case 6:  // TCP
                            info.protocol = "TCP";
                            if (header.len >= 54) {
                                const u_char *tcp_header = packet + 34;
                                info.sourcePort = ntohs(*(u_short*)tcp_header);
                                info.destinationPort = ntohs(*(u_short*)(tcp_header + 2));
                            }
                            break;
                        case 17: // UDP
                            info.protocol = "UDP";
                            if (header.len >= 42) {
                                const u_char *udp_header = packet + 34;
                                info.sourcePort = ntohs(*(u_short*)udp_header);
                                info.destinationPort = ntohs(*(u_short*)(udp_header + 2));
                            }
                            break;
                        case 1:  // ICMP
                            info.protocol = "ICMP";
                            break;
                        default:
                            info.protocol = QString("IP (%1)").arg(protocol);
                            break;
                    }
                } else {
                    info.protocol = "Other";
                    info.sourceIP = "Unknown";
                    info.destinationIP = "Unknown";
                }
            } else {
                info.protocol = "Unknown";
                info.sourceIP = "Unknown";
                info.destinationIP = "Unknown";
            }
            
            info.summary = QString("%1 -> %2 [%3] %4 bytes")
                .arg(info.sourceIP, info.destinationIP, info.protocol)
                .arg(info.length);
            
            emit packetCaptured(info);
        }
        
        msleep(1);
    }
    
    pcap_close(handle);
}

// Implementation of PacketAnalyzer
PacketAnalyzer::PacketAnalyzer(QObject *parent) 
    : QObject(parent), m_worker(nullptr), m_isCapturing(false) {}

PacketAnalyzer::~PacketAnalyzer() {
    stopCapture();
}

bool PacketAnalyzer::startCapture(const QString &interface) {
    if (m_isCapturing) return false;
    
    m_worker = new PacketCaptureWorker(interface, this);
    connect(m_worker, &PacketCaptureWorker::packetCaptured,
            this, &PacketAnalyzer::packetCaptured);
    connect(m_worker, &PacketCaptureWorker::errorOccurred,
            this, &PacketAnalyzer::errorOccurred);
    connect(m_worker, &PacketCaptureWorker::finished,
            m_worker, &QObject::deleteLater);
    
    m_worker->start();
    m_isCapturing = true;
    return true;
}

void PacketAnalyzer::stopCapture() {
    if (m_worker && m_isCapturing) {
        m_worker->stop();
        m_worker->wait(3000);
        m_worker = nullptr;
        m_isCapturing = false;
    }
}

QStringList PacketAnalyzer::getNetworkInterfaces() {
    QStringList interfaces;
    
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&alldevs, errbuf) != -1) {
        for (pcap_if_t *device = alldevs; device; device = device->next) {
            QString name = QString::fromLocal8Bit(device->name);
            
            // Skip loopback
            if (name == "lo" || name.startsWith("lo:")) continue;
            
            QString description = name;
            if (name.startsWith("eth")) description = "Ethernet (" + name + ")";
            else if (name.startsWith("wlan") || name.startsWith("wlp")) description = "WiFi (" + name + ")";
            else if (name.startsWith("enp")) description = "Ethernet (" + name + ")";
            
            interfaces.append(QString("%1|%2").arg(description, name));
        }
        pcap_freealldevs(alldevs);
    }
    
    if (interfaces.isEmpty()) {
        interfaces.append("No interfaces found - Run as root/Administrator|");
    }
    
    return interfaces;
}

// MainWindow Implementation
MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setupUI();
    
    setWindowTitle("Packet Analyzer - Professional Network Tool");
    setMinimumSize(1200, 800);
    resize(1400, 1000);
    
    // Apply dark theme
    setStyleSheet(getDarkTheme());
    
    // Initialize components
    m_analyzer = new PacketAnalyzer(this);
    m_packetCount = 0;
    
    // Connect signals
    connect(m_analyzer, &PacketAnalyzer::packetCaptured, 
            this, &MainWindow::onPacketCaptured);
    connect(m_packetTable, &QTableWidget::currentCellChanged,
            this, &MainWindow::onPacketTableSelectionChanged);
    
    // Update network interfaces
    updateInterfaces();
    
    // Status bar
    statusBar()->showMessage("Ready - Packet Analyzer v1.0");
}

void MainWindow::setupUI() {
    QWidget *centralWidget = new QWidget;
    setCentralWidget(centralWidget);
    
    QHBoxLayout *mainLayout = new QHBoxLayout(centralWidget);
    QSplitter *splitter = new QSplitter(Qt::Horizontal);
    
    // Left panel
    QWidget *leftPanel = new QWidget;
    leftPanel->setMaximumWidth(350);
    setupLeftPanel(leftPanel);
    
    // Right panel
    QWidget *rightPanel = new QWidget;
    setupRightPanel(rightPanel);
    
    splitter->addWidget(leftPanel);
    splitter->addWidget(rightPanel);
    splitter->setSizes({350, 1050});
    
    mainLayout->addWidget(splitter);
}

void MainWindow::setupLeftPanel(QWidget *parent) {
    QVBoxLayout *layout = new QVBoxLayout(parent);
    
    // Capture section
    QGroupBox *captureGroup = new QGroupBox("Packet Capture");
    QVBoxLayout *captureLayout = new QVBoxLayout(captureGroup);
    
    // Interface selection
    captureLayout->addWidget(new QLabel("Network Interface:"));
    m_interfaceCombo = new QComboBox;
    captureLayout->addWidget(m_interfaceCombo);
    
    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout;
    m_startButton = new QPushButton("Start Capture");
    m_stopButton = new QPushButton("Stop Capture");
    m_startButton->setObjectName("startButton");
    m_stopButton->setObjectName("stopButton");
    m_stopButton->setEnabled(false);
    
    buttonLayout->addWidget(m_startButton);
    buttonLayout->addWidget(m_stopButton);
    captureLayout->addLayout(buttonLayout);
    
    // Progress
    m_captureProgress = new QProgressBar;
    m_captureProgress->setRange(0, 0);
    m_captureProgress->setVisible(false);
    captureLayout->addWidget(m_captureProgress);
    
    // Status
    m_statusLabel = new QLabel("Ready to capture");
    m_statusLabel->setStyleSheet("color: #8e8e93; font-size: 12px;");
    captureLayout->addWidget(m_statusLabel);
    
    m_packetCountLabel = new QLabel("Packets: 0");
    m_packetCountLabel->setStyleSheet("color: #34C759; font-weight: bold;");
    captureLayout->addWidget(m_packetCountLabel);
    
    layout->addWidget(captureGroup);
    
    // Controls section
    QGroupBox *controlGroup = new QGroupBox("Controls");
    QVBoxLayout *controlLayout = new QVBoxLayout(controlGroup);
    
    QPushButton *clearBtn = new QPushButton("Clear Packets");
    QPushButton *scanBtn = new QPushButton("Scan Network");
    QPushButton *sendBtn = new QPushButton("Send Test Packet");
    QPushButton *saveBtn = new QPushButton("Save Packets");
    
    controlLayout->addWidget(clearBtn);
    controlLayout->addWidget(scanBtn);
    controlLayout->addWidget(sendBtn);
    controlLayout->addWidget(saveBtn);
    
    layout->addWidget(controlGroup);
    layout->addStretch();
    
    // Credits
    QLabel *creditsLabel = new QLabel("Made by Nytso2");
    creditsLabel->setStyleSheet("color: #666666; font-size: 10px; margin: 5px;");
    creditsLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(creditsLabel);
    
    // Store scan button reference
    m_scanButton = scanBtn;
    
    // Connect buttons
    connect(m_startButton, &QPushButton::clicked, this, &MainWindow::startCapture);
    connect(m_stopButton, &QPushButton::clicked, this, &MainWindow::stopCapture);
    connect(clearBtn, &QPushButton::clicked, this, &MainWindow::clearPackets);
    connect(scanBtn, &QPushButton::clicked, this, &MainWindow::scanNetwork);
    connect(sendBtn, &QPushButton::clicked, this, &MainWindow::sendTestPacket);
    connect(saveBtn, &QPushButton::clicked, this, &MainWindow::savePackets);
}

void MainWindow::setupRightPanel(QWidget *parent) {
    QVBoxLayout *layout = new QVBoxLayout(parent);
    
    QGroupBox *packetGroup = new QGroupBox("Captured Packets");
    QVBoxLayout *packetLayout = new QVBoxLayout(packetGroup);
    
    // Packet table
    m_packetTable = new QTableWidget;
    m_packetTable->setColumnCount(7);
    QStringList headers = {"ID", "Time", "Source IP", "Dest IP", "Protocol", "Length", "Summary"};
    m_packetTable->setHorizontalHeaderLabels(headers);
    m_packetTable->setAlternatingRowColors(true);
    m_packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_packetTable->horizontalHeader()->setStretchLastSection(true);
    m_packetTable->verticalHeader()->setVisible(false);
    
    // Set column widths
    m_packetTable->setColumnWidth(0, 50);   // ID
    m_packetTable->setColumnWidth(1, 100);  // Time
    m_packetTable->setColumnWidth(2, 120);  // Source IP
    m_packetTable->setColumnWidth(3, 120);  // Dest IP
    m_packetTable->setColumnWidth(4, 80);   // Protocol
    m_packetTable->setColumnWidth(5, 80);   // Length
    
    packetLayout->addWidget(m_packetTable);
    
    // Packet details
    packetLayout->addWidget(new QLabel("Packet Details:"));
    m_packetDetails = new QTextEdit;
    m_packetDetails->setMaximumHeight(200);
    m_packetDetails->setReadOnly(true);
    m_packetDetails->setPlaceholderText("Select a packet to view details...");
    m_packetDetails->setFont(QFont("Consolas", 9));
    packetLayout->addWidget(m_packetDetails);
    
    layout->addWidget(packetGroup);
}

void MainWindow::startCapture() {
    if (m_isCapturing) return;
    
    QString selectedInterface = getSelectedInterface();
    if (selectedInterface.isEmpty()) {
        QMessageBox::warning(this, "Warning", "Please select a network interface.");
        return;
    }
    
    if (m_analyzer->startCapture(selectedInterface)) {
        m_isCapturing = true;
        m_startButton->setEnabled(false);
        m_stopButton->setEnabled(true);
        m_captureProgress->setVisible(true);
        m_statusLabel->setText("Capturing packets...");
        statusBar()->showMessage("Packet capture started");
    } else {
        QMessageBox::critical(this, "Error", "Failed to start packet capture. Please run as root/administrator.");
    }
}

void MainWindow::stopCapture() {
    if (!m_isCapturing) return;
    
    m_analyzer->stopCapture();
    m_isCapturing = false;
    m_startButton->setEnabled(true);
    m_stopButton->setEnabled(false);
    m_captureProgress->setVisible(false);
    m_statusLabel->setText("Capture stopped");
    statusBar()->showMessage("Packet capture stopped");
}

void MainWindow::clearPackets() {
    m_packetTable->setRowCount(0);
    m_packetDetails->clear();
    m_packetData.clear();
    m_packetCount = 0;
    updatePacketCount();
}

// Network scanning with nmap
void MainWindow::scanNetwork() {
    m_scanButton->setEnabled(false);
    m_scanButton->setText("Scanning...");
    statusBar()->showMessage("Starting nmap network scan...");
    
    QThread *scanThread = QThread::create([this]() {
        QStringList devices;
        
        QString localIP = getLocalIPAddress();
        if (localIP.isEmpty()) {
            QMetaObject::invokeMethod(this, [this]() {
                QMessageBox::warning(this, "Warning", "Could not determine local IP address.");
                m_scanButton->setEnabled(true);
                m_scanButton->setText("Scan Network");
            });
            return;
        }
        
        QMetaObject::invokeMethod(this, [this, localIP]() {
            statusBar()->showMessage(QString("Detected local IP: %1").arg(localIP));
        });
        
        // Determine network range
        QString networkRange;
        if (localIP.startsWith("172.16.")) {
            networkRange = "172.16.0.0/23";
        } else if (localIP.startsWith("192.168.")) {
            QStringList parts = localIP.split('.');
            networkRange = parts[0] + "." + parts[1] + "." + parts[2] + ".0/24";
        } else if (localIP.startsWith("10.")) {
            networkRange = "10.0.0.0/8";
        } else {
            QStringList parts = localIP.split('.');
            networkRange = parts[0] + "." + parts[1] + "." + parts[2] + ".0/24";
        }
        
        devices.append(QString("%1 (This Computer - LOCAL)").arg(localIP));
        
        if (!isNmapAvailable()) {
            QMetaObject::invokeMethod(this, [this]() {
                QMessageBox::warning(this, "nmap Not Found", 
                    "nmap is not installed. Install it with:\nsudo apt install nmap");
                m_scanButton->setEnabled(true);
                m_scanButton->setText("Scan Network");
            });
            return;
        }
        
        QMetaObject::invokeMethod(this, [this, networkRange]() {
            statusBar()->showMessage(QString("Running nmap scan on %1...").arg(networkRange));
        });
        
        QStringList nmapResults = runNmapScan(networkRange);
        devices.append(nmapResults);
        
        QString networkBase = localIP.startsWith("172.16.") ? "172.16." : localIP.section('.', 0, 2) + ".";
        QMetaObject::invokeMethod(this, [this, devices, networkBase]() {
            updateScanResults(devices, networkBase);
        });
    });
    
    connect(scanThread, &QThread::finished, scanThread, &QThread::deleteLater);
    scanThread->start();
}

void MainWindow::sendTestPacket() {
    QString dstIP = "8.8.8.8";
    int port = 80;
    
    bool ok;
    dstIP = QInputDialog::getText(this, "Send Test Packet", 
                                 "Enter destination IP:", QLineEdit::Normal, dstIP, &ok);
    if (!ok || dstIP.isEmpty()) return;
    
    port = QInputDialog::getInt(this, "Send Test Packet", 
                               "Enter destination port:", port, 1, 65535, 1, &ok);
    if (!ok) return;
    
    if (sendTCPPacket("", dstIP, port)) {
        QMessageBox::information(this, "Success", 
            QString("Test packet sent to %1:%2").arg(dstIP).arg(port));
        statusBar()->showMessage(QString("Packet sent to %1:%2").arg(dstIP, QString::number(port)));
    } else {
        QMessageBox::warning(this, "Error", "Failed to send packet. Run as root/Administrator.");
    }
}

void MainWindow::savePackets() {
    if (m_packetData.isEmpty()) {
        QMessageBox::information(this, "No Data", "No packets to save.");
        return;
    }
    
    QString fileName = QFileDialog::getSaveFileName(this, 
        "Save Packets", 
        QString("packets_%1.json").arg(QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss")),
        "JSON Files (*.json);;Text Files (*.txt);;All Files (*)");
        
    if (fileName.isEmpty()) return;
    
    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Error", "Could not open file for writing.");
        return;
    }
    
    QTextStream out(&file);
    
    if (fileName.endsWith(".json")) {
        QJsonArray packetsArray;
        for (auto it = m_packetData.begin(); it != m_packetData.end(); ++it) {
            const PacketInfo &packet = it.value();
            QJsonObject packetObj;
            packetObj["id"] = packet.id;
            packetObj["timestamp"] = packet.timestamp.toString(Qt::ISODate);
            packetObj["sourceIP"] = packet.sourceIP;
            packetObj["destinationIP"] = packet.destinationIP;
            packetObj["protocol"] = packet.protocol;
            packetObj["sourcePort"] = packet.sourcePort;
            packetObj["destinationPort"] = packet.destinationPort;
            packetObj["length"] = packet.length;
            packetObj["summary"] = packet.summary;
            packetObj["rawData"] = QString(packet.rawData.toHex());
            packetsArray.append(packetObj);
        }
        
        QJsonObject root;
        root["packets"] = packetsArray;
        root["exportTime"] = QDateTime::currentDateTime().toString(Qt::ISODate);
        root["packetCount"] = packetsArray.size();
        
        QJsonDocument doc(root);
        out << doc.toJson();
    } else {
        out << "Packet Analyzer Export\n";
        out << "Generated: " << QDateTime::currentDateTime().toString() << "\n";
        out << "Total Packets: " << m_packetData.size() << "\n\n";
        for (auto it = m_packetData.begin(); it != m_packetData.end(); ++it) {
            const PacketInfo &packet = it.value();
            out << QString("%1\t%2\t%3\t%4\t%5\t%6\t%7\n")
                   .arg(packet.id)
                   .arg(packet.timestamp.toString("hh:mm:ss.zzz"))
                   .arg(packet.sourceIP)
                   .arg(packet.destinationIP)
                   .arg(packet.protocol)
                   .arg(packet.length)
                   .arg(packet.summary);
        }
    }
    
    file.close();
    QMessageBox::information(this, "Success", 
        QString("Saved %1 packets to %2").arg(m_packetData.size()).arg(fileName));
}

void MainWindow::onPacketCaptured(const PacketInfo &packet) {
    int row = m_packetTable->rowCount();
    m_packetTable->insertRow(row);
    
    m_packetTable->setItem(row, 0, new QTableWidgetItem(QString::number(packet.id)));
    m_packetTable->setItem(row, 1, new QTableWidgetItem(packet.timestamp.toString("hh:mm:ss.zzz")));
    m_packetTable->setItem(row, 2, new QTableWidgetItem(packet.sourceIP));
    m_packetTable->setItem(row, 3, new QTableWidgetItem(packet.destinationIP));
    m_packetTable->setItem(row, 4, new QTableWidgetItem(packet.protocol));
    m_packetTable->setItem(row, 5, new QTableWidgetItem(QString::number(packet.length)));
    m_packetTable->setItem(row, 6, new QTableWidgetItem(packet.summary));
    
    m_packetData[row] = packet;
    m_packetTable->scrollToBottom();
    
    m_packetCount++;
    updatePacketCount();
}

void MainWindow::onPacketTableSelectionChanged() {
    int currentRow = m_packetTable->currentRow();
    if (currentRow >= 0 && m_packetData.contains(currentRow)) {
        const PacketInfo &packet = m_packetData[currentRow];
        
        QString details = QString(
            "Packet ID: %1\n"
            "Timestamp: %2\n"
            "Source: %3:%4\n"
            "Destination: %5:%6\n"
            "Protocol: %7\n"
            "Length: %8 bytes\n"
            "Summary: %9\n\n"
            "Raw Data (first 256 bytes):\n%10"
        ).arg(packet.id)
         .arg(packet.timestamp.toString())
         .arg(packet.sourceIP).arg(packet.sourcePort)
         .arg(packet.destinationIP).arg(packet.destinationPort)
         .arg(packet.protocol)
         .arg(packet.length)
         .arg(packet.summary)
         .arg(QString(packet.rawData.left(256).toHex()));
        
        m_packetDetails->setPlainText(details);
    }
}

void MainWindow::updateInterfaces() {
    m_interfaceCombo->clear();
    m_interfaceCombo->addItems(m_analyzer->getNetworkInterfaces());
    if (m_interfaceCombo->count() == 0) {
        m_interfaceCombo->addItem("No interfaces found - Run as root/Administrator");
    }
}

QString MainWindow::getSelectedInterface() {
    QString selected = m_interfaceCombo->currentText();
    if (selected.contains("|")) {
        return selected.split("|").last();
    }
    return selected;
}

QString MainWindow::getLocalIPAddress() {
    struct ifaddrs *ifaddrs_ptr;
    QString localIP;
    
    if (getifaddrs(&ifaddrs_ptr) == 0) {
        for (struct ifaddrs *ifa = ifaddrs_ptr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                QString name = QString(ifa->ifa_name);
                if (name != "lo" && !name.startsWith("lo:")) {
                    struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
                    localIP = QString(inet_ntoa(addr->sin_addr));
                    break;
                }
            }
        }
        freeifaddrs(ifaddrs_ptr);
    }
    
    return localIP;
}

bool MainWindow::pingHost(const QString &host) {
    QString command = QString("ping -c 1 -W 2 -q %1").arg(host);
    
    QProcess process;
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start(command);
    
    if (!process.waitForFinished(5000)) {
        process.kill();
        return false;
    }
    
    return process.exitCode() == 0;
}

bool MainWindow::tcpPing(const QString &host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.toLocal8Bit().data(), &addr.sin_addr);
    
    int result = ::connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    if (result == 0) {
        ::close(sock);
        return true;
    }
    
    if (errno == EINPROGRESS) {
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);
        
        struct timeval timeout;
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        
        result = select(sock + 1, NULL, &writefds, NULL, &timeout);
        ::close(sock);
        return result > 0;
    }
    
    ::close(sock);
    return false;
}

QString MainWindow::getHostname(const QString &ip) {
    struct sockaddr_in sa;
    char hostname[NI_MAXHOST];
    
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.toLocal8Bit().data(), &sa.sin_addr);
    
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostname, NI_MAXHOST, nullptr, 0, 0) == 0) {
        return QString(hostname);
    }
    
    return "Unknown";
}

bool MainWindow::sendTCPPacket(const QString &, const QString &dstIP, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, dstIP.toLocal8Bit().data(), &dest.sin_addr);
    
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    
    ::connect(sock, (struct sockaddr*)&dest, sizeof(dest));
    ::close(sock);
    
    return true;
}

bool MainWindow::isNmapAvailable() {
    QProcess process;
    process.start("nmap", QStringList() << "--version");
    process.waitForFinished(3000);
    return process.exitCode() == 0;
}

QStringList MainWindow::runNmapScan(const QString &networkRange) {
    QStringList devices;
    
    QProcess process;
    QStringList arguments;
    arguments << "-sn"                    // Ping scan only
              << "--max-retries" << "2"   // Max 2 retries
              << "--host-timeout" << "3s" // 3 second timeout per host
              << networkRange;
    
    qDebug() << "Running nmap command:" << "nmap" << arguments.join(" ");
    
    process.start("nmap", arguments);
    if (!process.waitForFinished(60000)) { // 60 second timeout
        process.kill();
        qDebug() << "nmap scan timed out";
        return devices;
    }
    
    if (process.exitCode() != 0) {
        qDebug() << "nmap failed with exit code:" << process.exitCode();
        return devices;
    }
    
    QString output = process.readAllStandardOutput();
    qDebug() << "nmap output:" << output;
    
    // Parse nmap output for IP and MAC addresses
    QStringList lines = output.split('\n');
    QString currentIP;
    QString currentMAC;
    
    for (const QString &line : lines) {
        QString trimmed = line.trimmed();
        
        if (trimmed.startsWith("Nmap scan report for")) {
            // Save previous device if we have one
            if (!currentIP.isEmpty()) {
                QString deviceInfo = currentIP;
                if (!currentMAC.isEmpty()) {
                    deviceInfo += QString(" - MAC: %1").arg(currentMAC);
                }
                devices.append(deviceInfo);
            }
            
            // Extract IP from current line
            QRegularExpression ipRegex(R"(\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b)");
            QRegularExpressionMatch match = ipRegex.match(trimmed);
            
            if (match.hasMatch()) {
                currentIP = match.captured(1);
                currentMAC.clear(); // Reset MAC for new device
                qDebug() << "Found IP:" << currentIP;
            }
        }
        else if (trimmed.startsWith("MAC Address:")) {
            // Extract MAC: "MAC Address: 00:50:E8:10:07:96 (Nomadix)"
            QRegularExpression macRegex(R"(MAC Address:\s+([0-9A-Fa-f:]{17}))");
            QRegularExpressionMatch match = macRegex.match(trimmed);
            if (match.hasMatch()) {
                currentMAC = match.captured(1);
                qDebug() << "Found MAC:" << currentMAC << "for IP:" << currentIP;
            }
        }
    }
    
    // Don't forget the last device
    if (!currentIP.isEmpty()) {
        QString deviceInfo = currentIP;
        if (!currentMAC.isEmpty()) {
            deviceInfo += QString(" - MAC: %1").arg(currentMAC);
        }
        devices.append(deviceInfo);
    }
    
    return devices;
}

void MainWindow::updateScanResults(const QStringList &devices, const QString &networkBase) {
    m_scanButton->setEnabled(true);
    m_scanButton->setText("Scan Network");
    
    QString message = QString("Network scan completed - %1 devices found").arg(devices.size());
    statusBar()->showMessage(message);
    
    QDialog *resultsDialog = new QDialog(this);
    resultsDialog->setWindowTitle("Network Scan Results");
    resultsDialog->setModal(true);
    resultsDialog->resize(600, 500);
    
    QVBoxLayout *layout = new QVBoxLayout(resultsDialog);
    
    QLabel *titleLabel = new QLabel(QString("Found %1 active devices:").arg(devices.size()));
    titleLabel->setStyleSheet("font-weight: bold; font-size: 14px; margin: 10px; color: #ffffff;");
    layout->addWidget(titleLabel);
    
    QTextEdit *deviceList = new QTextEdit;
    deviceList->setReadOnly(true);
    
    if (devices.isEmpty()) {
        deviceList->setPlainText("No devices found.\n\nTroubleshooting tips:\n"
                                "1. Make sure you're connected to a network\n"
                                "2. Try running as root/administrator: sudo ./PacketAnalyzer\n"
                                "3. Check if nmap is installed: nmap --version\n"
                                "4. Your network might block ping (ICMP)");
    } else {
        deviceList->setPlainText(devices.join("\n"));
    }
    layout->addWidget(deviceList);
    
    QHBoxLayout *buttonLayout = new QHBoxLayout;
    QPushButton *closeButton = new QPushButton("Close");
    
    buttonLayout->addStretch();
    buttonLayout->addWidget(closeButton);
    layout->addLayout(buttonLayout);
    
    connect(closeButton, &QPushButton::clicked, resultsDialog, &QDialog::accept);
    
    resultsDialog->show();
}

void MainWindow::updatePacketCount() {
    m_packetCountLabel->setText(QString("Packets: %1").arg(m_packetCount));
}

QString MainWindow::getDarkTheme() {
    return R"(
        QMainWindow { background-color: #1e1e1e; color: #ffffff; }
        QGroupBox { 
            font-weight: bold; border: 1px solid #3c3c3c; border-radius: 8px; 
            margin-top: 10px; padding-top: 10px; background-color: #2d2d2d; 
        }
        QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 8px 0 8px; color: #ffffff; }
        QPushButton { 
            background-color: #007AFF; border: none; border-radius: 8px; 
            padding: 8px 16px; color: white; font-weight: 500; min-height: 20px; 
        }
        QPushButton:hover { background-color: #0056CC; }
        QPushButton:disabled { background-color: #3c3c3c; color: #8e8e93; }
        QPushButton#startButton { background-color: #34C759; }
        QPushButton#startButton:hover { background-color: #2DB54A; }
        QPushButton#stopButton { background-color: #FF3B30; }
        QPushButton#stopButton:hover { background-color: #E6342A; }
        QTableWidget { 
            background-color: #2d2d2d; alternate-background-color: #363636; 
            selection-background-color: #007AFF; gridline-color: #3c3c3c; 
            border: 1px solid #3c3c3c; border-radius: 6px; color: #ffffff;
        }
        QTableWidget::item {
            color: #ffffff;
            padding: 4px;
        }
        QTableWidget::item:selected {
            background-color: #007AFF;
            color: #ffffff;
        }
        QHeaderView::section { 
            background-color: #3c3c3c; color: white; padding: 6px; 
            border: none; border-right: 1px solid #4c4c4c; 
        }
        QComboBox { 
            background-color: #3c3c3c; border: 1px solid #5c5c5c; 
            border-radius: 6px; padding: 6px; color: white; 
        }
        QComboBox::drop-down {
            border: none;
            background-color: #007AFF;
            border-radius: 3px;
        }
        QComboBox::down-arrow {
            image: none;
            border-style: solid;
            border-width: 3px;
            border-color: transparent transparent white transparent;
        }
        QComboBox QAbstractItemView {
            background-color: #3c3c3c;
            color: white;
            selection-background-color: #007AFF;
            border: 1px solid #5c5c5c;
        }
        QLineEdit { 
            background-color: #3c3c3c; border: 1px solid #5c5c5c; 
            border-radius: 6px; padding: 6px; color: white; 
        }
        QTextEdit { 
            background-color: #2d2d2d; border: 1px solid #3c3c3c; 
            border-radius: 6px; color: white; 
        }
        QProgressBar { 
            border: 1px solid #3c3c3c; border-radius: 6px; 
            background-color: #2d2d2d; text-align: center; color: white; 
        }
        QProgressBar::chunk { background-color: #007AFF; border-radius: 5px; }
        QLabel { color: #ffffff; }
        QDialog {
            background-color: #1e1e1e;
            color: #ffffff;
        }
        QDialog QTextEdit {
            background-color: #2d2d2d;
            color: #ffffff;
            border: 1px solid #3c3c3c;
        }
        QDialog QPushButton {
            background-color: #007AFF;
            color: white;
            border: none;
            border-radius: 6px;
            padding: 8px 16px;
        }
        QDialog QPushButton:hover {
            background-color: #0056CC;
        }
        QDialog QLabel {
            color: #ffffff;
        }
    )";
}

#include "main.moc"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    
    app.setApplicationName("Packet Analyzer");
    app.setApplicationVersion("1.0.0");
    
    QMessageBox::information(nullptr, "Admin Required", 
        "This application requires root/Administrator privileges for packet capture.\n"
        "Please run as root/Administrator.");
    
    MainWindow window;
    window.show();
    
    return app.exec();
}