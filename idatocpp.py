import argparse
import json
import csv
import re 
import os

parser = argparse.ArgumentParser(description='IDA .h and .cpp wrapper file generator.')
parser.add_argument('-db', required=True, metavar='path', type=str,
                    help='The path to IDA generated database using plugin-sdk tool.')
parser.add_argument('-iclass', required=True, metavar='name', type=str,
                    help='The class name in the IDB.')
parser.add_argument('--rcalls', action='store_true', 
                    help='Adds <className>_Reversed wrappers for virtual functions.')
parser.add_argument('--pdtypes', action='store_true', 
                    help='Function parameter types will be extracted from the demangled name rather than the function prototype.')
args = parser.parse_args()

reversedWrappers = args.rcalls
extractTypesFromDemangledName = args.pdtypes
className = args.iclass
structFilePath = args.db + "\\structs\\gtaout." + className + ".json"
variablesFilePath =  args.db + "\\plugin-sdk.out.variables.csv"
functionsFilePath =  args.db + "\\plugin-sdk.out.functions.csv"
class_members_h = ""
static_vars_h = ""
static_vars_cpp = ""
functions_h = ""
functions_cpp = ""
inject_hooks_cpp = ""

def replace_all(text, dic):
    for i, j in dic.items():
        text = re.sub(i,j,text)
    return text

def GetProperType(text):
    if text.strip() == "char":
        return "std::int8_t"
    replacements = {
        r'\bunsigned __int8\b':'std::uint8_t', 
        r'\bunsigned __int16\b':'std::uint16_t', 
        r'\bunsigned __int32\b':'std::uint32_t', 
        r'\b__int8\b':'std::int8_t', 
        r'\b__int16\b':'std::int16_t', 
        r'\b__int32\b':'std::int32_t', 
        r'\b_BYTE\b':'std::uint8_t', 
        r'\bword\b':'std::int16_t', 
        r'\b_WORD\b':'std::int16_t', 
        r'\bWORD\b':'std::int16_t', 
        r'\bsigned int\b':'std::int32_t', 
        r'\bunsigned int\b':'std::uint32_t',
        r'\bint\b':'std::int32_t', 
        r'\bdword\b':'std::int32_t', 
        r'\b_DWORD\b':'std::int32_t',  
        r'\bstruct\b':'', 
        r'\b_BOOL1\b':'bool', 
    }
    return replace_all(text, replacements).strip()


def GetTypeData(theType):
    if '[' in theType:
        realType = theType.split("[")[0].replace(" ", "")
        result = re.findall(r"\[\s*\+?(-?\d+)\s*\]", theType) 
        if len(result) > 0: 
            for i in range(len(result)):
                result[i] = int(result[i])
            return { "type" : GetProperType(realType), "arrays" : result}
    elif '*' in theType:
        realType = theType.split("*")[0].strip()
        return { "type" : GetProperType(realType), "isPointer" : True }
    return { "type" : GetProperType(theType) }


structInfo = None
isStaticClass = False
if not os.path.isfile(structFilePath):
    isStaticClass = True
else:
    with open(structFilePath) as f:
        structInfo = json.load(f)
        for member in structInfo["members"]:
            typeData = GetTypeData(member["type"])
            if "arrays" in typeData:
                totalElements1 = typeData['arrays'][0]
                arrayLength = len(typeData['arrays']) 
                if arrayLength == 1:
                    class_members_h += "    %s %s[%d];\n" % (typeData['type'], member["name"], totalElements1)
                if arrayLength == 2:
                    totalElements2 = typeData['arrays'][1]
                    class_members_h += "    %s %s[%d][%d];\n" % (typeData['type'], member["name"], totalElements1, totalElements2)
            elif "isPointer" in typeData:
                class_members_h += "    %s* %s;\n" % (typeData['type'], member["name"])
            else:
                class_members_h += "    %s %s;\n" % (typeData['type'], member["name"])

classIdentifier = className + "::"

if os.path.isfile(variablesFilePath):
    with open(variablesFilePath,'rt', encoding='UTF-8') as f:
        data = csv.reader(f)
        for row in data:
            address = row[0]
            demangledName = row[3]
            theType = row[4]
            sizeInBytes = row[6]
            findIndex = demangledName.find(classIdentifier)
            if findIndex == 0:
                #print (str(findIndex) + " | " + demangledName + " | type: " + theType + " | sizeInBytes: " + str(sizeInBytes)) 
                variableName = demangledName.strip(classIdentifier)
                staticVarData = GetTypeData(theType)
                if "arrays" in staticVarData:
                    totalElements1 = staticVarData['arrays'][0]
                    arrayLength = len(staticVarData['arrays']) 
                    if arrayLength == 1:
                        static_vars_h += "    static %s(&%s)[%d];\n" % (staticVarData['type'], variableName, totalElements1)
                        static_vars_cpp += "%s(&%s)[%d] = *(%s(*)[%d])%s;\n" % (staticVarData['type'], 
                            demangledName, totalElements1, staticVarData['type'], totalElements1, address) 
                    if arrayLength == 2:
                        totalElements2 = staticVarData['arrays'][1]
                        static_vars_h += "    static %s(&%s)[%d][%d];\n" % (staticVarData['type'], variableName, totalElements1, totalElements2)
                        static_vars_cpp += "%s(&%s)[%d][%d] = *(%s(*)[%d][%d])%s;\n" % (staticVarData['type'], 
                            demangledName, totalElements1, totalElements2, staticVarData['type'], totalElements1, totalElements2, address)
                elif "isPointer" in staticVarData:
                    static_vars_h += "    static %s*& %s;\n" % (staticVarData['type'], variableName)
                    static_vars_cpp += "%s*& %s = *(%s**)%s;\n" % (staticVarData['type'], demangledName, staticVarData['type'], address)
                else:
                    static_vars_h += "    static %s& %s;\n" % (staticVarData['type'], variableName)
                    static_vars_cpp += "%s& %s = *(%s*)%s;\n" % (staticVarData['type'], demangledName, staticVarData['type'], address)

#print("\n")
#print (static_vars_h)
#print("\n")
#print (static_vars_cpp)

functionsList = []

with open(functionsFilePath,'rt', encoding='UTF-8') as f:
    data = csv.reader(f)
    for row in data:
        demangledName = row[3]
        findIndex = demangledName.find(classIdentifier)
        if findIndex == 0:
            vtableIndex = int(row[13])
            row[13] = vtableIndex
            functionsList.append(row)

functionsList.sort(key=lambda row: row[13]) # sort by vtable index

def GetParameterTypesFromDemangledName(demangledName):
    demangledName = demangledName.strip()
    startBracketIndex = demangledName.find('(')
    if startBracketIndex != -1:
        lastCharIndex = len(demangledName) - 1
        if demangledName[lastCharIndex] == ')':
            textWithinBrackets = demangledName[startBracketIndex+1:lastCharIndex].strip()
            if textWithinBrackets == "":
                return []
            parameterTypes = textWithinBrackets.split(',')
            if len(parameterTypes) == 1 and parameterTypes[0] == "void":
                return []
            return parameterTypes
    return []

def IsConstructorFunction(gtaClassName, functionName, classIdentifier):
    functionName = functionName.strip(" ").lower()
    if gtaClassName.lower() in functionName or "constructor" in functionName:
        return True
    return False

def IsDestructorFunction(gtaClassName, functionName, classIdentifier):
    functionName = functionName.strip(" ").lower()
    destructorName = "~" + gtaClassName.lower()
    if destructorName in functionName or "destructor" in functionName:
        return True
    return False

processedFunctions = {}
supportedCallingConventions = ["cdecl", "thiscall", "stdcall", "fastcall"]
def GenerateFunctionCode(constructorsOnly = False, destructorsOnly = False, constructorWrappersOnly = False, virtualFunctionsOnly = False):
    global functionsList
    global classIdentifier
    global args 
    global functions_h
    global functions_cpp
    global isStaticClass
    global processedFunctions
    global inject_hooks_cpp
    global extractTypesFromDemangledName

    virtual_functions_h = ""
    virtual_functions_cpp = ""
    for i in range(len(functionsList)):
        if i in processedFunctions:
            continue
        row = functionsList[i]
        address = row[0].strip()
        demangledName = row[3].strip()
        functionType = GetProperType(row[4].strip())
        callingConvention = row[5].strip()
        returnType = GetProperType(row[6])
        parameterNames = row[8].strip()
        vtableIndex = int(row[13])

        fullFunctionName = demangledName.split("(")[0]
        functionName = fullFunctionName.replace(classIdentifier, "").split("(")[0]
        if callingConvention not in supportedCallingConventions:
            raise Exception("calling convention '%s' not handled for function '%s'" % (callingConvention, fullFunctionName))
        paramTypesExtractedFromDemangledName = False
        parameterTypes = []
        if extractTypesFromDemangledName:
            if "<" in demangledName:
                print ("%s: `pdtypes` option ignored due to template usage" % fullFunctionName)
            else:
                parameterTypes = GetParameterTypesFromDemangledName(demangledName)
        if len(parameterTypes) > 0:
            paramTypesExtractedFromDemangledName = True
        else:
            parameterTypes = row[7].strip()
            if parameterTypes != "":
                parameterTypes = parameterTypes.split("~")
            else:
                parameterTypes = []
        if parameterNames != "":
            parameterNames = parameterNames.split("~")
        else:
            parameterNames = []
            
        if returnType == "" and not isStaticClass:
            print ("%s: Skipping, return type is empty" % fullFunctionName)
            continue
        if constructorsOnly and not IsConstructorFunction(className, functionName, classIdentifier):
            continue
        if destructorsOnly and not IsDestructorFunction(className, functionName, classIdentifier):
            continue
        if constructorWrappersOnly and not IsConstructorFunction(className, functionName, classIdentifier):
            continue
        if virtualFunctionsOnly and vtableIndex == -1:
            continue
        # we need this check to avoid duplicates because the destructor function can also be a virtual function
        if not destructorsOnly and IsDestructorFunction(className, functionName, classIdentifier):
            continue
        if not constructorsOnly: # this check is needed to make constructorWrappersOnly option generate code
            processedFunctions[i] = True
        if callingConvention == "thiscall" or callingConvention == "fastcall":
            # remove the first parameter type and name (this pointer)
            if paramTypesExtractedFromDemangledName:
                del parameterNames[0]
            else:
                del parameterNames[0]
                del parameterTypes[0]
        parameterTypesStr = ""
        parameterNamesStr = ""
        paramterTypesNamesStr = ""
        totalParameters = len(parameterTypes)
        for i in range(totalParameters):
            theType = GetProperType(parameterTypes[i]).strip()
            theName = parameterNames[i].strip()
            parameterTypesStr += theType
            parameterNamesStr += theName
            paramterTypesNamesStr += "%s %s" % (theType, theName)
            if i != totalParameters-1:
                parameterTypesStr += ", "
                parameterNamesStr += ", "
                paramterTypesNamesStr += ", "

        if constructorsOnly and IsConstructorFunction(className, functionName, classIdentifier):
            inject_hooks_cpp += "    HookInstall(%s, &%s::Constructor);\n" % (address, className)
            functions_h += "    %s(%s);\n" % (className, paramterTypesNamesStr)
            functions_cpp += "%s::%s(%s)\n{\n}\n\n" % (className, className, paramterTypesNamesStr)
            continue
        if destructorsOnly and IsDestructorFunction(className, functionName, classIdentifier):
            inject_hooks_cpp += "    HookInstall(%s, &%s::Destructor);\n" % (address, className)
            functions_h += "    ~%s();\n" % className 
            functions_cpp += "%s::~%s()\n{\n}\n\n" % (className, className) 
            functions_h += "    %s* Destructor();\n" % className
            functions_cpp += "%s* %s::Destructor()\n{\n    this->%s::~%s();\n    return this;\n}\n\n" % (className, className, className, className)
            break # break the loop because a class should not have more than 1 destructor
        if constructorWrappersOnly and IsConstructorFunction(className, functionName, classIdentifier):
            functions_h += "    %s* Constructor(%s);\n" % (className, paramterTypesNamesStr)
            functions_cpp += "%s* %s::Constructor(%s)\n{\n    this->%s::%s(%s);\n    return this;\n}\n\n" % (className, className, paramterTypesNamesStr, className, className, parameterNamesStr)
            continue
        elif vtableIndex != -1:
            if reversedWrappers:
                inject_hooks_cpp += "    HookInstall(%s, &%s_Reversed);\n" % (address, fullFunctionName)
            functions_h += "    %s %s(%s) override;\n" % (returnType, functionName, paramterTypesNamesStr)
            functions_cpp += "%s %s(%s)\n{\n" % (returnType, fullFunctionName, paramterTypesNamesStr)
            if reversedWrappers:
                functions_cpp += "#ifdef USE_DEFAULT_FUNCTIONS\n"
                virtual_functions_h += "    %s %s_Reversed(%s);\n" % (returnType, functionName, paramterTypesNamesStr)
                virtual_functions_cpp += "%s %s_Reversed(%s)\n{\n}\n\n" % (returnType, fullFunctionName, paramterTypesNamesStr)
        elif callingConvention  == "fastcall":
            inject_hooks_cpp += "    HookInstall(%s, &%s);\n" % (address, fullFunctionName)
            functions_h += "    static %s __fastcall %s(%s);\n" % (returnType, functionName, paramterTypesNamesStr)
            functions_cpp += "%s __fastcall %s(%s)\n{\n" % (returnType, fullFunctionName, paramterTypesNamesStr)
        elif callingConvention  == "stdcall":
            inject_hooks_cpp += "    HookInstall(%s, &%s);\n" % (address, fullFunctionName)
            functions_h += "    static %s __stdcall %s(%s);\n" % (returnType, functionName, paramterTypesNamesStr)
            functions_cpp += "%s __stdcall %s(%s)\n{\n" % (returnType, fullFunctionName, paramterTypesNamesStr)
        elif callingConvention == "cdecl":
            inject_hooks_cpp += "    HookInstall(%s, &%s);\n" % (address, fullFunctionName)
            functions_h += "    static %s %s(%s);\n" % (returnType, functionName, paramterTypesNamesStr)
            functions_cpp += "%s %s(%s)\n{\n" % (returnType, fullFunctionName, paramterTypesNamesStr)
        else:
            inject_hooks_cpp += "    HookInstall(%s, &%s);\n" % (address, fullFunctionName)
            functions_h += "    %s %s(%s);\n" % (returnType, functionName, paramterTypesNamesStr)
            functions_cpp += "%s %s(%s)\n{\n" % (returnType, fullFunctionName, paramterTypesNamesStr)

        parameterNamesCommaStr = ""
        if totalParameters > 0:
            parameterTypesStr = ", %s" % parameterTypesStr
            if callingConvention == "thiscall" or callingConvention == "fastcall":
                parameterNamesCommaStr = ", %s" % parameterNamesStr
            else:
                parameterNamesCommaStr = parameterNamesStr

        if callingConvention == "thiscall":
            if returnType == "void":
                functions_cpp += "    return plugin::CallMethod<%s, %s*%s>(this%s);\n" % ( 
                    address, className, parameterTypesStr, parameterNamesCommaStr) 
            else:
                functions_cpp += "    return plugin::CallMethodAndReturn<%s, %s, %s*%s>(this%s);\n" % (returnType, 
                    address, className, parameterTypesStr, parameterNamesCommaStr) 
        elif callingConvention  == "fastcall":
            if returnType == "void":
                functions_cpp += "    return plugin::FastCall<%s, %s*%s>(this%s);\n" % ( 
                    address, className, parameterTypesStr, parameterNamesCommaStr) 
            else:
                functions_cpp += "    return plugin::FastCallAndReturn<%s, %s, %s*%s>(this%s);\n" % (returnType, 
                    address, className, parameterTypesStr, parameterNamesCommaStr) 
        elif callingConvention == "stdcall" or isStaticClass:
            if returnType == "void":
                functions_cpp += "    return plugin::StdCall<%s%s>(%s);\n" % ( 
                    address, parameterTypesStr, parameterNamesCommaStr) 
            else:
                functions_cpp += "    return plugin::StdCallAndReturn<%s, %s%s>(%s);\n" % (returnType, 
                    address, parameterTypesStr, parameterNamesCommaStr)
        elif callingConvention == "cdecl" or isStaticClass:
            if returnType == "void":
                functions_cpp += "    return plugin::Call<%s%s>(%s);\n" % ( 
                    address, parameterTypesStr, parameterNamesCommaStr) 
            else:
                functions_cpp += "    return plugin::CallAndReturn<%s, %s%s>(%s);\n" % (returnType, 
                    address, parameterTypesStr, parameterNamesCommaStr) 
        else:
            raise Exception("calling convention '%s' not handled for function '%s'" % (callingConvention, fullFunctionName))

        if vtableIndex != -1 and reversedWrappers:
            functions_cpp += "#else\n    return %s_Reversed(%s);\n#endif\n}\n\n" % (fullFunctionName, parameterNamesStr)
        else:
            functions_cpp += "}\n\n"

    if virtualFunctionsOnly and reversedWrappers and not isStaticClass:
        functions_h += "\nprivate:\n" + virtual_functions_h + "public:\n"
        functions_cpp += "\n" + virtual_functions_cpp

GenerateFunctionCode(constructorsOnly = True)
GenerateFunctionCode(destructorsOnly = True)
functions_h += "private:\n"
GenerateFunctionCode(constructorWrappersOnly = True)
functions_h += "public:\n"
GenerateFunctionCode(virtualFunctionsOnly = True)
GenerateFunctionCode()

functions_h = "    static void InjectHooks();\n\n" + functions_h
functions_cpp = "void %s::InjectHooks()\n{\n%s}\n\n%s" % (className, inject_hooks_cpp, functions_cpp)
final_code_h = "class %s {\npublic:\n" % (className)
if not isStaticClass:
    final_code_h += class_members_h
if static_vars_h != "":
    final_code_h += "\n%s\n%s\n}\n\n" % (static_vars_h, functions_h)
else:
    final_code_h += "\n%s\n};\n\n" % functions_h
if not isStaticClass:
    final_code_h += "VALIDATE_SIZE(%s, %s);\n" % (className, structInfo["size"])
if static_vars_cpp != "":
    final_code_cpp = '#include "StdInc.h"\n\n%s\n%s' % (static_vars_cpp, functions_cpp)
else:
    final_code_cpp = '#include "StdInc.h"\n\n%s' % functions_cpp

def createOutputFile(filePath, contents):
    file = open(filePath,"w+")
    file.write(contents)
    file.close()

outputPath = "output"
if not os.path.exists(outputPath):
    os.mkdir(outputPath)
createOutputFile("%s\\%s.h" % (outputPath, className), final_code_h)
createOutputFile("%s\\%s.cpp" % (outputPath, className), final_code_cpp)
 
