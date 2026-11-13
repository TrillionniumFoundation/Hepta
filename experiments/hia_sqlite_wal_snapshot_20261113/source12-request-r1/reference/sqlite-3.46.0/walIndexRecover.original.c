static int walIndexRecover(Wal *pWal){
  int rc;                         /* Return Code */
  i64 nSize;                      /* Size of log file */
  u32 aFrameCksum[2] = {0, 0};
  int iLock;                      /* Lock offset to lock for checkpoint */

  /* Obtain an exclusive lock on all byte in the locking range not already
  ** locked by the caller. The caller is guaranteed to have locked the
  ** WAL_WRITE_LOCK byte, and may have also locked the WAL_CKPT_LOCK byte.
  ** If successful, the same bytes that are locked here are unlocked before
  ** this function returns.
  */
  assert( pWal->ckptLock==1 || pWal->ckptLock==0 );
  assert( WAL_ALL_BUT_WRITE==WAL_WRITE_LOCK+1 );
  assert( WAL_CKPT_LOCK==WAL_ALL_BUT_WRITE );
  assert( pWal->writeLock );
  iLock = WAL_ALL_BUT_WRITE + pWal->ckptLock;
  rc = walLockExclusive(pWal, iLock, WAL_READ_LOCK(0)-iLock);
  if( rc ){
    return rc;
  }

  WALTRACE(("WAL%p: recovery begin...\n", pWal));

  memset(&pWal->hdr, 0, sizeof(WalIndexHdr));

  rc = sqlite3OsFileSize(pWal->pWalFd, &nSize);
  if( rc!=SQLITE_OK ){
    goto recovery_error;
  }

  if( nSize>WAL_HDRSIZE ){
    u8 aBuf[WAL_HDRSIZE];         /* Buffer to load WAL header into */
    u32 *aPrivate = 0;            /* Heap copy of *-shm hash being populated */
    u8 *aFrame = 0;               /* Malloc'd buffer to load entire frame */
    int szFrame;                  /* Number of bytes in buffer aFrame[] */
    u8 *aData;                    /* Pointer to data part of aFrame buffer */
    int szPage;                   /* Page size according to the log */
    u32 magic;                    /* Magic value read from WAL header */
    u32 version;                  /* Magic value read from WAL header */
    int isValid;                  /* True if this frame is valid */
    u32 iPg;                      /* Current 32KB wal-index page */
    u32 iLastFrame;               /* Last frame in wal, based on nSize alone */

    /* Read in the WAL header. */
    rc = sqlite3OsRead(pWal->pWalFd, aBuf, WAL_HDRSIZE, 0);
    if( rc!=SQLITE_OK ){
      goto recovery_error;
    }

    /* If the database page size is not a power of two, or is greater than
    ** SQLITE_MAX_PAGE_SIZE, conclude that the WAL file contains no valid
    ** data. Similarly, if the 'magic' value is invalid, ignore the whole
    ** WAL file.
    */
    magic = sqlite3Get4byte(&aBuf[0]);
    szPage = sqlite3Get4byte(&aBuf[8]);
    if( (magic&0xFFFFFFFE)!=WAL_MAGIC
     || szPage&(szPage-1)
     || szPage>SQLITE_MAX_PAGE_SIZE
     || szPage<512
    ){
      goto finished;
    }
    pWal->hdr.bigEndCksum = (u8)(magic&0x00000001);
    pWal->szPage = szPage;
    pWal->nCkpt = sqlite3Get4byte(&aBuf[12]);
    memcpy(&pWal->hdr.aSalt, &aBuf[16], 8);

    /* Verify that the WAL header checksum is correct */
    walChecksumBytes(pWal->hdr.bigEndCksum==SQLITE_BIGENDIAN,
        aBuf, WAL_HDRSIZE-2*4, 0, pWal->hdr.aFrameCksum
    );
    if( pWal->hdr.aFrameCksum[0]!=sqlite3Get4byte(&aBuf[24])
     || pWal->hdr.aFrameCksum[1]!=sqlite3Get4byte(&aBuf[28])
    ){
      goto finished;
    }

    /* Verify that the version number on the WAL format is one that
    ** are able to understand */
    version = sqlite3Get4byte(&aBuf[4]);
    if( version!=WAL_MAX_VERSION ){
      rc = SQLITE_CANTOPEN_BKPT;
      goto finished;
    }

    /* Malloc a buffer to read frames into. */
    szFrame = szPage + WAL_FRAME_HDRSIZE;
    aFrame = (u8 *)sqlite3_malloc64(szFrame + WALINDEX_PGSZ);
    SEH_FREE_ON_ERROR(0, aFrame);
    if( !aFrame ){
      rc = SQLITE_NOMEM_BKPT;
      goto recovery_error;
    }
    aData = &aFrame[WAL_FRAME_HDRSIZE];
    aPrivate = (u32*)&aData[szPage];

    /* Read all frames from the log file. */
    iLastFrame = (nSize - WAL_HDRSIZE) / szFrame;
    for(iPg=0; iPg<=(u32)walFramePage(iLastFrame); iPg++){
      u32 *aShare;
      u32 iFrame;                 /* Index of last frame read */
      u32 iLast = MIN(iLastFrame, HASHTABLE_NPAGE_ONE+iPg*HASHTABLE_NPAGE);
      u32 iFirst = 1 + (iPg==0?0:HASHTABLE_NPAGE_ONE+(iPg-1)*HASHTABLE_NPAGE);
      u32 nHdr, nHdr32;
      rc = walIndexPage(pWal, iPg, (volatile u32**)&aShare);
      assert( aShare!=0 || rc!=SQLITE_OK );
      if( aShare==0 ) break;
      SEH_SET_ON_ERROR(iPg, aShare);
      pWal->apWiData[iPg] = aPrivate;

      for(iFrame=iFirst; iFrame<=iLast; iFrame++){
        i64 iOffset = walFrameOffset(iFrame, szPage);
        u32 pgno;                 /* Database page number for frame */
        u32 nTruncate;            /* dbsize field from frame header */

        /* Read and decode the next log frame. */
        rc = sqlite3OsRead(pWal->pWalFd, aFrame, szFrame, iOffset);
        if( rc!=SQLITE_OK ) break;
        isValid = walDecodeFrame(pWal, &pgno, &nTruncate, aData, aFrame);
        if( !isValid ) break;
        rc = walIndexAppend(pWal, iFrame, pgno);
        if( NEVER(rc!=SQLITE_OK) ) break;

        /* If nTruncate is non-zero, this is a commit record. */
        if( nTruncate ){
          pWal->hdr.mxFrame = iFrame;
          pWal->hdr.nPage = nTruncate;
          pWal->hdr.szPage = (u16)((szPage&0xff00) | (szPage>>16));
          testcase( szPage<=32768 );
          testcase( szPage>=65536 );
          aFrameCksum[0] = pWal->hdr.aFrameCksum[0];
          aFrameCksum[1] = pWal->hdr.aFrameCksum[1];
        }
      }
      pWal->apWiData[iPg] = aShare;
      SEH_SET_ON_ERROR(0,0);
      nHdr = (iPg==0 ? WALINDEX_HDR_SIZE : 0);
      nHdr32 = nHdr / sizeof(u32);
#ifndef SQLITE_SAFER_WALINDEX_RECOVERY
      /* Memcpy() should work fine here, on all reasonable implementations.
      ** Technically, memcpy() might change the destination to some
      ** intermediate value before setting to the final value, and that might
      ** cause a concurrent reader to malfunction.  Memcpy() is allowed to
      ** do that, according to the spec, but no memcpy() implementation that
      ** we know of actually does that, which is why we say that memcpy()
      ** is safe for this.  Memcpy() is certainly a lot faster.
      */
      memcpy(&aShare[nHdr32], &aPrivate[nHdr32], WALINDEX_PGSZ-nHdr);
#else
      /* In the event that some platform is found for which memcpy()
      ** changes the destination to some intermediate value before
      ** setting the final value, this alternative copy routine is
      ** provided.
      */
      {
        int i;
        for(i=nHdr32; i<WALINDEX_PGSZ/sizeof(u32); i++){
          if( aShare[i]!=aPrivate[i] ){
            /* Atomic memory operations are not required here because if
            ** the value needs to be changed, that means it is not being
            ** accessed concurrently. */
            aShare[i] = aPrivate[i];
          }
        }
      }
#endif
      SEH_INJECT_FAULT;
      if( iFrame<=iLast ) break;
    }

    SEH_FREE_ON_ERROR(aFrame, 0);
    sqlite3_free(aFrame);
  }

finished:
  if( rc==SQLITE_OK ){
    volatile WalCkptInfo *pInfo;
    int i;
    pWal->hdr.aFrameCksum[0] = aFrameCksum[0];
    pWal->hdr.aFrameCksum[1] = aFrameCksum[1];
    walIndexWriteHdr(pWal);

    /* Reset the checkpoint-header. This is safe because this thread is
    ** currently holding locks that exclude all other writers and
    ** checkpointers. Then set the values of read-mark slots 1 through N.
    */
    pInfo = walCkptInfo(pWal);
    pInfo->nBackfill = 0;
    pInfo->nBackfillAttempted = pWal->hdr.mxFrame;
    pInfo->aReadMark[0] = 0;
    for(i=1; i<WAL_NREADER; i++){
      rc = walLockExclusive(pWal, WAL_READ_LOCK(i), 1);
      if( rc==SQLITE_OK ){
        if( i==1 && pWal->hdr.mxFrame ){
          pInfo->aReadMark[i] = pWal->hdr.mxFrame;
        }else{
          pInfo->aReadMark[i] = READMARK_NOT_USED;
        }
        SEH_INJECT_FAULT;
        walUnlockExclusive(pWal, WAL_READ_LOCK(i), 1);
      }else if( rc!=SQLITE_BUSY ){
        goto recovery_error;
      }
    }

    /* If more than one frame was recovered from the log file, report an
    ** event via sqlite3_log(). This is to help with identifying performance
    ** problems caused by applications routinely shutting down without
    ** checkpointing the log file.
    */
    if( pWal->hdr.nPage ){
      sqlite3_log(SQLITE_NOTICE_RECOVER_WAL,
          "recovered %d frames from WAL file %s",
          pWal->hdr.mxFrame, pWal->zWalName
      );
    }
  }

recovery_error:
  WALTRACE(("WAL%p: recovery %s\n", pWal, rc ? "failed" : "ok"));
  walUnlockExclusive(pWal, iLock, WAL_READ_LOCK(0)-iLock);
  return rc;
}
