# SecuringTheCloud
_Demonstration of applied public and private key encryption, using Python and the cryptography library Fernet_

## Overview

The goal of this assignment was to implement a secure cloud storage application for a cloud storage service of our choice. For my implementation, I chose to use Google Drive. The application provides users of a ‘secure cloud storage group’ (defined from within the application) the ability to upload encrypted files to the service, as well as download any encrypted file another cloud storage group member has uploaded and be able to read it in plain-text form. To anyone else viewing the file, the file should appear to be encrypted and its contents must not be salvageable to anyone not registered with the group. In other words, to those viewing the files outside the context of the application, the files will be securely encrypted. It is only in the process of downloading the files through the application that the decryption process takes place via application of the appropriate encryption key. 

In addition, the solution for representing the secure cloud storage group should provide the ability to add  and  remove  users  from  the  group.  While  encryption  alone  can  prevent  snoopers  on  the  network  from reading the contents of communications (so-called '*man in the middle* attacks), the file contents must be further protected from attacks through the use of public key certificates, which are used to verify the identity of the sender of a communication.

My implementation was completed in Python and consists of two scripts; ``CloudAccessManager.py`` and ``CloudGroupClient.py``, henceforth referred to as ‘CAM’ and ‘client’ respectively. Both scripts are set up to communicate via sockets, and the intention is that CAM would be placed on some central server.  The  CAM  is the gatekeeper for access to the Google Drive account for those in the cloud group. The Client would serve as the interface  through  which  members  of  the  secure  cloud  storage  group  can  interface  with  the  CAM,  and  would transmit requests for file uploads and downloads from some local machine to the server on which the CAM is located.

*For further discussion, please see report.pdf*
