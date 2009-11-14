/***************************************************************************
 *   Copyright (C) 2009 by Eduardo Robles Elvira <edulix@gmail.com>        *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA .        *
 ***************************************************************************/
#include "ui_mainwindowclass.h"
#include "config.h"
#ifdef HAVE_KLEO_SUPPORT
#include <kleo/ui/keyselectiondialog.h>
#include <kleo/ui/keyrequester.h>
#include <kleo/cryptobackendfactory.h>
#include <kleo/cryptobackend.h>
#include <kleo/encryptjob.h>
#include <kleo/decryptjob.h>
#endif
#include <gpgme++/key.h>
#include <gpgme++/encryptionresult.h>
#include <gpgme++/decryptionresult.h>

#include <kdebug.h>
#include <kaboutdata.h>
#include <kapplication.h>
#include <kdebug.h>
#include <kmessagebox.h>
#include <klocale.h>
#include <kcmdlineargs.h>

#include <QWidget>
#include <QLabel>
#include <QMainWindow>

using namespace Kleo;
using namespace GpgME;

class KleoDialog : public QMainWindow
{
    Q_OBJECT
    
public:
    KleoDialog(QWidget *parent = 0)
        : QMainWindow(parent), ui(new Ui::MainWindowClass), backend(CryptoBackendFactory::instance()->protocol( OpenPGP ))
    {
        Q_ASSERT( backend );
        
        ui->setupUi(this);
        connect(ui->selectPrivateKeyButton, SIGNAL(clicked()), this, SLOT(selectKey()));
        connect(ui->encryptButton, SIGNAL(clicked()), this, SLOT(encrypt()));
        connect(ui->decryptButton, SIGNAL(clicked()), this, SLOT(decrypt()));
        ui->encryptButton->setEnabled(false);
        ui->decryptButton->setEnabled(false);
    }
    
    ~KleoDialog() { delete ui; }
        
    private Q_SLOTS:
        void selectKey()
        {
            Kleo::KeySelectionDialog dlg("Kleo::KeySelectionDialog Test",
                                    "Please select a key:",
                                    std::vector<GpgME::Key>(),
                                    Kleo::KeySelectionDialog::SecretKeys | Kleo::KeySelectionDialog::OpenPGPKeys,
                                    true,
                                    false);

            if ( dlg.exec() == QDialog::Accepted && (dlg.selectedKeys().size() > 0) ) {
                gpgkey = dlg.selectedKeys().front();
                ui->encryptButton->setEnabled(true);
                ui->decryptButton->setEnabled(true);
                
                ui->label->setText(gpgkey.userID(0).id());
                statusBar()->clearMessage();
            } else {
                statusBar()->showMessage(tr("No key selected"));
            }       
        }
        
        void encrypt()
        {
            QByteArray plainText = ui->textEdit->toPlainText().toAscii();
            
            if(plainText.startsWith("-----BEGIN PGP MESSAGE-----")) {
                statusBar()->showMessage(tr("Message is already encryped, press decrypt button instead"));
                return;
            }
            
            QByteArray cipherText; // Here we will store the cipher text
            std::vector<GpgME::Key> recipients(1, gpgkey);
            
            std::auto_ptr<Kleo::EncryptJob> encryptJob( backend->encryptJob( /*armor=*/true, /*textmode=*/true ) );
            Q_ASSERT( encryptJob.get() );
            encryptJob->setOutputIsBase64Encoded(false);
            GpgME::EncryptionResult res = encryptJob->exec(recipients, plainText, true, cipherText);
            ui->textEdit->setPlainText(cipherText);
            statusBar()->clearMessage();
        }
        
        void decrypt()
        {
            QByteArray cipherText = ui->textEdit->toPlainText().toAscii();
            QByteArray plainText;
            std::auto_ptr<Kleo::DecryptJob> decryptJob( backend->decryptJob() );
            Q_ASSERT( decryptJob.get() );
            DecryptionResult res = decryptJob->exec(cipherText, plainText);
            
            if(plainText.isEmpty()) {
                statusBar()->showMessage(tr("Couldn't decrypt the message"));
                return;
            }
            ui->textEdit->setPlainText(plainText);
            statusBar()->clearMessage();
        }
    
    private: 
        Ui::MainWindowClass *ui;
        const CryptoBackend::Protocol * const backend;
        GpgME::Key gpgkey;
};

int main(int argc, char **argv)
{
    KAboutData *data = new KAboutData("kleocypher", "kleocypher", ki18n("kleocypher"), "1.0",
                                      ki18n("A small application to test libkleo functionality"),
                                      KAboutData::License_GPL , ki18n("2009 Eduardo Robles Elvira"));
    data->addAuthor(ki18n("Eduardo Robles Elvira"), ki18n("Maintainer"), "edulix@gmail.com", "http://blog.edulix.es");

    KCmdLineArgs::init(argc, argv, data);
    KApplication app;

    KleoDialog example;
    example.show();
    
    return app.exec();
}

#include "main.moc"
