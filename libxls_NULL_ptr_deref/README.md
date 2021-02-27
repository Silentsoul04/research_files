# libxls xls_parseWorkSheet() - NULL pointer dereference

## INTRODUCTION

A NULL pointer dereference vulnerability has been detected in the function `xls_parseWorkSheet()` when trying to access the `rdi` register that is NULL at that time. 

Looking at the code we can realize it is because of trying to access `long offset = pWS->filepos;` to that pointer, which is the argument for the function.

The argument for `xls_parseWorkSheet()` comes from the return value of `xls_getWorkSheet()`:

```c
pWS = xls_getWorkSheet(pWB, i);
xls_parseWorkSheet(pWS);
```

If we enter the function `xls_getWorkSheet()`:

```c
xlsWorkSheet * xls_getWorkSheet(xlsWorkBook* pWB,int num)
{
    xlsWorkSheet * pWS = NULL;
    verbose ("xls_getWorkSheet");
    if (num >= 0 && num < (int)pWB->sheets.count) {
        pWS = calloc(1, sizeof(xlsWorkSheet));
        pWS->filepos=pWB->sheets.sheet[num].filepos;
        pWS->workbook=pWB;
        pWS->rows.lastcol=0;
        pWS->rows.lastrow=0;
        pWS->colinfo.count=0;
    }
    return pWS;
}
```

We can easily deduce that if either `num` is less than 0, or `num` is greater than `pWB->sheets.count` the conditional won't succeed, thus returning `pWS` directly without assigning it a heap chunk.

As the pointer has been initialized with NULL, a NULL pointer is returned, which will be the argument for the next function, and the program will crash when trying to access it.

## REPRODUCE

To reproduce this crash, the `test2_libxls` file has been used with a specially crafted XLS file.

The crafted file needs to have no `BoundSheet8` records to make `pWB->sheets.count` be 0.

```
root@ubuntu:/software/libxls-1.6.2# .libs/test2_libxls min/crash.xls 
ole2_open: min/crash.xls
libxls : xls_open_ole
libxls : xls_parseWorkBook
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 16
    Not Processed in parseWoorkBook():  BOF=0x3030 size=16
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 2
    Not Processed in parseWoorkBook():  BOF=0x3030 size=2
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 2
    Not Processed in parseWoorkBook():  BOF=0x3030 size=2
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 0
    Not Processed in parseWoorkBook():  BOF=0x3030 size=0
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 112
    Not Processed in parseWoorkBook():  BOF=0x3030 size=112
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 48
    Not Processed in parseWoorkBook():  BOF=0x3030 size=48
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 48
    Not Processed in parseWoorkBook():  BOF=0x3030 size=48
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 2
    Not Processed in parseWoorkBook():  BOF=0x3030 size=2
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 2
    Not Processed in parseWoorkBook():  BOF=0x3030 size=2
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 48
    Not Processed in parseWoorkBook():  BOF=0x3030 size=48
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 49
    Not Processed in parseWoorkBook():  BOF=0x3030 size=49
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 26880
    Not Processed in parseWoorkBook():  BOF=0x3030 size=26880
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 12336
    Not Processed in parseWoorkBook():  BOF=0x3030 size=12336
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 12336
    Not Processed in parseWoorkBook():  BOF=0x3030 size=12336
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 12336
    Not Processed in parseWoorkBook():  BOF=0x3030 size=12336
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 12336
    Not Processed in parseWoorkBook():  BOF=0x3030 size=12336
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 12336
    Not Processed in parseWoorkBook():  BOF=0x3030 size=12336
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 12336
    Not Processed in parseWoorkBook():  BOF=0x3030 size=12336
----------------------------------------------
libxls : BOF
   ID: 3030h Unknown ()
   Size: 12336
    Not Processed in parseWoorkBook():  BOF=0x3030 size=12336
----------------------------------------------
libxls : BOF
   ID: 000Ah EOF (End of File)
   Size: 48
libxls : xls_getWorkSheet
Segmentation fault
```

## ANALYSIS

As I explained in the Introduction section, we need `num` to be less than 0 or greater than `pWB->sheets.count`. Having one (or both) of those requirements can trigger the NULL pointer dereference.

In `main()`:

```c
for (i = 0; i < pWB->sheets.count; i++) {
	int isFirstLine = 1;
```

The first condition will never fail as `i` will always be greater or equal to 0.

Also, `i` cannot be greater than `pWB->sheets.count` as depends on it's value to be incremented.

But... what if `pWB->sheets.count` is equal to 0? Then `i` will be 0 too.

In the conditional `i` won't be less than `pWB->sheets.count`, but equal, thus failing the conditional.

The function `xls_addSheet()`, responsible for incrementing the `pWB->sheets.count` value is never executed with the current PoC xls file, thus keeping until crash time the value which the program gave it when being initialized at `xls_open_ole()`:

```c
pWB->sheets.count=0;
pWB->xfs.count=0;
pWB->fonts.count=0;
pWB->charset = strdup(charset ? charset : "UTF-8");
```

But how do we make the program to not execute `xls_addSheet()` ?

We initially need to avoid any `XLS_RECORD_BOUNDSHEET` record.

If we craft an XLS file that do not contain any `BoundSheet8` record, this code will never reached:

```c
case XLS_RECORD_BOUNDSHEET:
		{
			//printf("ADD SHEET\n");
			BOUNDSHEET *bs = (BOUNDSHEET *)buf;
        xlsConvertBoundsheet(bs);
			// different for BIFF5 and BIFF8
        if ((retval = xls_addSheet(pWB, bs, bof1.size)) != LIBXLS_OK) {
            goto cleanup;
        }
		}
    break;
```

And `pWB->sheets.count` will be 0 when reaching the conditional code.

The result is a SIGSEGV (Segmentation fault) interruption crashing the program trying to access non-mapped memory:

```
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "test2_libxls", stopped 0x7ffff7fab7cd in xls_parseWorkSheet (), reason: SIGSEGV
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7fab7cd → xls_parseWorkSheet(pWS=0x0)
[#1] 0x555555555545 → main(argc=<optimized out>, argv=0x7fffffffe378)
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p pWS
$9 = (xlsWorkSheet *) 0x0
gef➤  x/i $rip
=> 0x7ffff7fab7cd <xls_parseWorkSheet+77>:	mov    rdx,QWORD PTR [rdi+0x18]
gef➤  

```


## IMPACT

The most common issue with this type of vulnerability is a Denial of Service (DoS) once a crash has been triggered as demonstrated above with the crash PoC.

## SOLUTION

A solution for this issue could be adding a pointer check before using it, and change the actions once a pointer is detected to be NULL.

Patch example:

```c
xls_error_t xls_parseWorkSheet(xlsWorkSheet* pWS)
{
    BOF tmp;
    BYTE* buf = NULL;
    
    /* --- PATCH START --- */
    
    if(pWS == NULL)
    	return -1; // or any value to be checked from the parent function when failing
    
    /* --- PATCH END --- */
    	
    long offset = pWS->filepos;
    size_t read;
    xls_error_t retval = 0;

	struct st_cell_data *cell = NULL;
	xlsWorkBook *pWB = pWS->workbook;

    verbose ("xls_parseWorkSheet");

    if ((retval = xls_preparseWorkSheet(pWS)) != LIBXLS_OK) {
        goto cleanup;
    }
	// printf("size=%d fatpos=%d)\n", pWS->workbook->olestr->size, pWS->workbook->olestr->fatpos);

    if ((retval = xls_makeTable(pWS)) != LIBXLS_OK) {
        goto cleanup;
    }
```

Obviously, the pointer is used multiple times in the code, so having it NULL is something not expected. A more complex patch is needed to avoid unexpected results for the next functions to be executed instead of just returning if a NULL pointer is detected.

Anyway, a better solution for this patch is update the conditional at `xls_getWorkSheet()` to this:

```c
if (num >= 0 && num <= (int)pWB->sheets.count) {
```

This time, if `num` is equal to `pWB->sheets.count` the heap chunk will be returned avoiding a NULL pointer being returned.



