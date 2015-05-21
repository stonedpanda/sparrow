#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <iostream>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 **************************************************************************/ 
int tun_alloc(char *dev, int flags) {
	struct ifreq ifr;
	int fd, err;
	char *clonedev = "/dev/net/tun";

	if( (fd = open(clonedev , O_RDWR)) < 0 ) {
		perror("Opening /dev/net/tun");
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;

	if (*dev) {
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
		perror("ioctl(TUNSETIFF)");
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);

	return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n) {
	int nread;

	if((nread=read(fd, buf, n)) < 0){
		perror("Reading data");
		exit(1);
	}
	return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n) {
	int nwrite;

	if((nwrite=write(fd, buf, n)) < 0){
		perror("Writing data");
		exit(1);
	}
	return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {
	int nread, left = n;

	while(left > 0) {
		if ((nread = cread(fd, buf, left)) == 0) {
			return 0 ;      
		} else {
			left -= nread;
			buf += nread;
		}
	}
	return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...) {
	va_list argp;
  
	if(debug) {
		va_start(argp, msg);
		vfprintf(stderr, msg, argp);
		va_end(argp);
	}
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {
	va_list argp;
  
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "%s -I <ifacename> [-o] [-u|-a] [-d]\n", progname);
	fprintf(stderr, "%s -h\n", progname);
	fprintf(stderr, "\n");
	fprintf(stderr, "-I <ifacename>: Name of interface to use (mandatory)\n");
	fprintf(stderr, "-o <filename>: Database file on flash drive (mandatory)\n");
	fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
	fprintf(stderr, "-d: outputs debug information while running\n");
	fprintf(stderr, "-h: prints this help text\n");
	exit(1);
}

static int createBlobTable(sqlite3 *db) {
	const char *zSql = "CREATE TABLE packets (data BLOB)";
	return sqlite3_exec(db, zSql, 0, 0, 0);
}

static int writeBlob(sqlite3 *db, char *zBlob, int nBlob) {
	const char *zSql = "INSERT INTO packets(data) VALUES(?)";
	sqlite3_stmt *pStmt;
	int rc;

	do {
		rc = sqlite3_prepare(db, zSql, -1, &pStmt, 0);
		if(rc != SQLITE_OK) {
			return rc;
		}

		sqlite3_bind_blob(pStmt, 1, zBlob, nBlob, SQLITE_STATIC);

		rc = sqlite3_step(pStmt);
		assert(rc != SQLITE_ROW);

		rc = sqlite3_finalize(pStmt);
	} while(rc == SQLITE_SCHEMA);

	return rc;
}

static int readBlob(sqlite3 *db, char **pzBlob, int *pnBlob, int *rowid) {
	const char *zSql = "SELECT ROWID, data from packets LIMIT 1";
	sqlite3_stmt *pStmt;
	int rc;

	*pzBlob = 0;
	*pnBlob = 0;
	*rowid = 0;

	do {
		rc = sqlite3_prepare(db, zSql, -1, &pStmt, 0);
		if(rc != SQLITE_OK) {
			return rc;
		}

		rc = sqlite3_step(pStmt);
		if(rc == SQLITE_ROW) {
			*rowid = sqlite3_column_int(pStmt, 0);
			*pnBlob = sqlite3_column_bytes(pStmt, 1);
			*pzBlob = (char *)malloc(*pnBlob);
			memcpy(*pzBlob, sqlite3_column_blob(pStmt, 1), *pnBlob);
		}
		rc = sqlite3_finalize(pStmt);
	} while(rc == SQLITE_SCHEMA);

	return rc;
}

static int deleteBlob(sqlite3 *db, int rowid) {
	const char *zSql = "DELETE FROM packets WHERE ROWID = ?";
	sqlite3_stmt *pStmt;
	int rc;

	do {
		rc = sqlite3_prepare(db, zSql, -1, &pStmt, 0);
		if(rc != SQLITE_OK) {
			return rc;
		}

		sqlite3_bind_int(pStmt, 1, rowid);

		rc = sqlite3_step(pStmt);
		assert(rc != SQLITE_ROW);

		rc = sqlite3_finalize(pStmt);
	} while(rc == SQLITE_SCHEMA);

	return rc;
}

static void freeBlob(unsigned char *zBlob) {
	free(zBlob);
}

int main(int argc, char *argv[]) {
	char *db_file;
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	unsigned char **pzBlob;
	int *pnBlob;
	int tap_fd, option;
	int flags = IFF_TUN;
	char if_name[IFNAMSIZ] = "";
	int maxfd;
	uint16_t nread, nwrite, plength;
	char buffer[BUFSIZE];
	int sock_fd, net_fd, optval = 1;
	socklen_t remotelen;
	int cliserv = -1;    /* must be specified on cmd line */
	unsigned long int tap2usb = 0, usb2tap = 0;

	progname = argv[0];
  
	/* Check command line options */
	while((option = getopt(argc, argv, "I:o:uahd")) > 0) {
		switch(option) {
			case 'd':
				debug = 1;
				break;
			case 'h':
				usage();
				break;
			case 'I':
				strncpy(if_name,optarg, IFNAMSIZ-1);
				break;
			case 'o':
				db_file = optarg;
				break;
			case 'u':
				flags = IFF_TUN;
				break;
			case 'a':
				flags = IFF_TAP;
				break;
			default:
				my_err("Unknown option %c\n", option);
				usage();
		}
	}

	argv += optind;
	argc -= optind;

	if(argc > 0) {
		my_err("Too many options!\n");
		usage();
	}

	if(*if_name == '\0') {
		my_err("Must specify interface name!\n");
		usage();
	}

	rc = sqlite3_open(db_file, &db);
	createBlobTable(db);

	if(rc) {
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return(1);
	}

	/* initialize tun/tap interface */
	if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
		my_err("Error connecting to tun/tap interface %s!\n", if_name);
		exit(1);
	}

	do_debug("Successfully connected to interface %s\n", if_name);

	std::cout << "USB to TAP" << std::endl;
	std::cout << "Start Transfer..." << std::endl;
	std::cout << "Press enter to continue." << std::endl;
	std::cin.ignore();

	char *zBlob;

	// USB to TAP
	while(1) {
		// data from usb: read it, and write it to tun/tap interface

		int rowid;
		int nBlob;

		/* read packet */
		readBlob(db, &zBlob, &nBlob, &rowid);

		if(nBlob == 0) {
			break;
		}

		do_debug("USB2TAP %lu: Read %d bytes from the usb\n", usb2tap, nBlob);

		for(int i = 0; i < nBlob; i++) {
			buffer[i] = zBlob[i];
		}

		/* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
		nwrite = cwrite(tap_fd, buffer, nBlob);
		do_debug("USB2TAP %lu: Written %d bytes to the tap interface\n", usb2tap, nBlob);
		// Remove packet from database
		deleteBlob(db, rowid);
		usb2tap++;
	}

	// TAP to USB
	while(1) {
		// data from tun/tap: just read it and write it to usb
      
		nread = cread(tap_fd, buffer, BUFSIZE);

		do_debug("TAP2USB %lu: Read %d bytes from the tap interface\n", tap2usb, nread);

		char* zBlob = new char[nread];
		for(int i = 0; i < nread; i++) {
			zBlob[i] = buffer[i];
		}

		writeBlob(db, zBlob, nread);

		do_debug("TAP2USB %lu: Written %d bytes to the usb\n", tap2usb, nread);
		tap2usb++;
	}
	sqlite3_close(db);

	std::cout << "Press enter to close." << std::endl;
	std::cin.ignore();

	return(0);
}