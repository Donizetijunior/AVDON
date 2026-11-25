rule High_Entropy_PE_UPX
{
    meta:
        description = "PE file packed with UPX"
    strings:
        $mz = { 4D 5A }
        $upx0 = "UPX0"
        $upx1 = "UPX1"
    condition:
        any of them
}
