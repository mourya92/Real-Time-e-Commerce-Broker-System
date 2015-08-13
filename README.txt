-------------------------------------------------------------------------------------------------------------------------------------------------
				IMPLEMENTATION OF REAL TIME E-COMMERCE BROKER SYSTEM
-------------------------------------------------------------------------------------------------------------------------------------------------
The project files are found in the NetSec_Stable folder and the contain the following files & directories:
1. NetSec_Stable/src/ contains all the .java source code files.
2. Files folder contains all the Public keys along with the listed products in the E Commerce site.

-------------------------------------------------------------------------------------------------------------------------------------------------


Steps to Compile and Execute the Project:
1. Copy the .zip file to required folder on the UTD CS Unix Machine. This can be done by logging into utdvpn.utdallas.edu.
2. Login to net01.utdallas.edu and locate the zip folder. The contents of the folder is unzipped using the command 'unzip NetSec.zip'.
3. Using the cd command, navigate to the 'src' directory and the list of .java source files are obtained.
4. To compile all the .java files, type the command 'javac -XDignore.symbol.file *.java'. All the .java files are complied and are ready to be executed
5. Run the Client program in the net01.utdallas.edu machine using the command: 'java Client'
6. Run the Broker program in the net02.utdallas.edu machine using the command: 'java Broker'
7. Run the Amazon webserver in the net03.utdallas.edu machine using the command: 'java Amazon'
8. Run the Ebay webserver in the net04.utdallas.edu machine using the command: 'java Ebay'
9. In the net01/Client, Enter the name of the Web Server as Amazon or Ebay Ex. PLEASE ENTER THE WEB SERVER: Amazon
10. Now, Enter the User name as 'kk' Ex. PLEASE ENTER USER NAME: kk
11. Enter password as 'kk' Ex. PLEASE ENTER PASSWORD: kk
12. Enter a generic name for the product for which the catalogue is to be obtained. 
The product catalogs we have programmed are
movies
songs
images
13. Once the Product Catalogue is received,you should see a list of products available under that category of products
    enter the required Product ID. Ex. ENTER PRODUCT ID: 10003
14. Along with the Product ID, the price of the product corresponding to the Product Id is to be entered. Ex. ENTER PAYMENT: 6
15. Once the Product is selected and the Payment is made, the Product is received in the respective "Products" folder.

Kindly let us know if you have any doubts.
--------------------------------------------------------------------------------------------------------------------------------------------------