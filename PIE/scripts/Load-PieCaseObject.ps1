using namespace System
using namespace System.IO
using namespace System.Collections.Generic
Function Get-PieCaseObject 
{
    Param(
        [String] $CaseObject
    )

    $PIEData = Get-Content $CaseObject | ConvertFrom-Json
    return $PIEData
}
Get-PieCaseObject -CaseObject $args[0]