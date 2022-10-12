.section .uboot_domd,"a"

/* DomD binary from include/ dir */
.incbin		"domain_bins/u-boot.bin"

.section .dtb_domd,"a"

/* DomD dtb from include/ dir */
.incbin		"domain_bins/uboot_minimal.dtb"

.section .dtb_domu,"a"
/* DomU dtb from include/ dir */
.incbin		"domain_bins/uboot_minimal_domu.dtb"
