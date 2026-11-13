static int walFindFrame(
  Wal *pWal,                      /* WAL handle */
  Pgno pgno,                      /* Database page number to read data for */
  u32 *piRead                     /* OUT: Frame number (or zero) */
){
  u32 iRead = 0;                  /* If !=0, WAL frame to return data from */
  u32 iLast = pWal->hdr.mxFrame;  /* Last page in WAL for this reader */
  int iHash;                      /* Used to loop through N hash tables */
  int iMinHash;

  /* This routine is only be called from within a read transaction. */
  assert( pWal->readLock>=0 || pWal->lockError );

  /* If the "last page" field of the wal-index header snapshot is 0, then
  ** no data will be read from the wal under any circumstances. Return early
  ** in this case as an optimization.  Likewise, if pWal->readLock==0,
  ** then the WAL is ignored by the reader so return early, as if the
  ** WAL were empty.
  */
  if( iLast==0 || (pWal->readLock==0 && pWal->bShmUnreliable==0) ){
    *piRead = 0;
    return SQLITE_OK;
  }

  /* Search the hash table or tables for an entry matching page number
  ** pgno. Each iteration of the following for() loop searches one
  ** hash table (each hash table indexes up to HASHTABLE_NPAGE frames).
  **
  ** This code might run concurrently to the code in walIndexAppend()
  ** that adds entries to the wal-index (and possibly to this hash
  ** table). This means the value just read from the hash
  ** slot (aHash[iKey]) may have been added before or after the
  ** current read transaction was opened. Values added after the
  ** read transaction was opened may have been written incorrectly -
  ** i.e. these slots may contain garbage data. However, we assume
  ** that any slots written before the current read transaction was
  ** opened remain unmodified.
  **
  ** For the reasons above, the if(...) condition featured in the inner
  ** loop of the following block is more stringent that would be required
  ** if we had exclusive access to the hash-table:
  **
  **   (aPgno[iFrame]==pgno):
  **     This condition filters out normal hash-table collisions.
  **
  **   (iFrame<=iLast):
  **     This condition filters out entries that were added to the hash
  **     table after the current read-transaction had started.
  */
  iMinHash = walFramePage(pWal->minFrame);
  for(iHash=walFramePage(iLast); iHash>=iMinHash; iHash--){
    WalHashLoc sLoc;              /* Hash table location */
    int iKey;                     /* Hash slot index */
    int nCollide;                 /* Number of hash collisions remaining */
    int rc;                       /* Error code */
    u32 iH;

    rc = walHashGet(pWal, iHash, &sLoc);
    if( rc!=SQLITE_OK ){
      return rc;
    }
    nCollide = HASHTABLE_NSLOT;
    iKey = walHash(pgno);
    SEH_INJECT_FAULT;
    while( (iH = AtomicLoad(&sLoc.aHash[iKey]))!=0 ){
      u32 iFrame = iH + sLoc.iZero;
      if( iFrame<=iLast && iFrame>=pWal->minFrame && sLoc.aPgno[iH-1]==pgno ){
        assert( iFrame>iRead || CORRUPT_DB );
        iRead = iFrame;
      }
      if( (nCollide--)==0 ){
        *piRead = 0;
        return SQLITE_CORRUPT_BKPT;
      }
      iKey = walNextHash(iKey);
    }
    if( iRead ) break;
  }

#ifdef SQLITE_ENABLE_EXPENSIVE_ASSERT
  /* If expensive assert() statements are available, do a linear search
  ** of the wal-index file content. Make sure the results agree with the
  ** result obtained using the hash indexes above.  */
  {
    u32 iRead2 = 0;
    u32 iTest;
    assert( pWal->bShmUnreliable || pWal->minFrame>0 );
    for(iTest=iLast; iTest>=pWal->minFrame && iTest>0; iTest--){
      if( walFramePgno(pWal, iTest)==pgno ){
        iRead2 = iTest;
        break;
      }
    }
    assert( iRead==iRead2 );
  }
#endif

  *piRead = iRead;
  return SQLITE_OK;
}
