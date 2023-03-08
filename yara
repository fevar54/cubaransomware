rule cuba_ransomware_behavior
{
    meta:
        description = "Detects behavior associated with Cuba ransomware"
        author = "FEVAR54

    strings:
        $string1 = "ApcHelper.sys" wide ascii
        $string2 = "fuga de LAPSUS NVIDIA" wide ascii

    condition:
        $string1 in (file.path, file.writes) and
        $string2 in (file.path, file.writes) and
        any of them
}
