//
// Published from https://github.com/wujingbo/SlickEdit-2013-for-edk2
//
// Macros for tracing EDK2 Language
//

#include "slick.sh"

// DEC (*.dec)
#define EDK2_DEC_LANGUAGE_ID   "edk2dec"
#define EDK2_DEC_LANGUAGE_NAME "EDK2 DEC"
    #define DEC_SETUP_INFO     'MN='EDK2_DEC_LANGUAGE_NAME',TABS=+2,MA=1 74 1,KEYTAB=ext-keys,WW=1,IWT=0,ST='0x0A',IN=2,WC=A-Za-z0-9_,LN='EDK2_DEC_LANGUAGE_NAME',CF=1,LNL=1,TL=0,BNDS=,'
    #define DEC_COMPILE_INFO   ''
    #define DEC_SYNTAX_INFO    '2 1 1 -1 0 0 0'
    #define DEC_BE_INFO        ''

// DSC (*.dsc, *.env)
#define EDK2_DSC_LANGUAGE_ID   "edk2dsc"
#define EDK2_DSC_LANGUAGE_NAME "EDK2 DSC"
    #define DSC_SETUP_INFO     'MN='EDK2_DSC_LANGUAGE_NAME',TABS=+2,MA=1 74 1,KEYTAB=ext-keys,WW=1,IWT=0,ST='0x0A',IN=2,WC=A-Za-z0-9_,LN='EDK2_DSC_LANGUAGE_NAME',CF=1,LNL=1,TL=0,BNDS=,'
    #define DSC_COMPILE_INFO   ''
    #define DSC_SYNTAX_INFO    '2 1 1 -1 0 0 0'
    #define DSC_BE_INFO        ''

// FDF (*.fdf)
#define EDK2_FDF_LANGUAGE_ID   "edk2fdf"
#define EDK2_FDF_LANGUAGE_NAME "EDK2 FDF"
    #define FDF_SETUP_INFO     'MN='EDK2_FDF_LANGUAGE_NAME',TABS=+2,MA=1 74 1,KEYTAB=ext-keys,WW=1,IWT=0,ST='0x0A',IN=2,WC=A-Za-z0-9_,LN='EDK2_FDF_LANGUAGE_NAME',CF=1,LNL=1,TL=0,BNDS=,'
    #define FDF_COMPILE_INFO   ''
    #define FDF_SYNTAX_INFO    '2 1 1 -1 0 0 0'
    #define FDF_BE_INFO        ''

// IDF (*.idf)
#define EDK2_IDF_LANGUAGE_ID   "edk2idf"
#define EDK2_IDF_LANGUAGE_NAME "EDK2 IDF"
    #define IDF_SETUP_INFO     'MN='EDK2_IDF_LANGUAGE_NAME',TABS=+2,MA=1 74 1,KEYTAB=ext-keys,WW=1,IWT=0,ST='0x0A',IN=2,WC=A-Za-z0-9_,LN='EDK2_IDF_LANGUAGE_NAME',CF=1,LNL=1,TL=0,BNDS=,'
    #define IDF_COMPILE_INFO   ''
    #define IDF_SYNTAX_INFO    '2 1 1 -1 0 0 0'
    #define IDF_BE_INFO        ''

// INF (*.inf)
#define EDK2_INF_LANGUAGE_ID   "edk2inf"
#define EDK2_INF_LANGUAGE_NAME "EDK2 INF"
    #define INF_SETUP_INFO     'MN='EDK2_INF_LANGUAGE_NAME',TABS=+2,MA=1 74 1,KEYTAB=ext-keys,WW=1,IWT=0,ST='0x0A',IN=2,WC=A-Za-z0-9_,LN='EDK2_INF_LANGUAGE_NAME',CF=1,LNL=1,TL=0,BNDS=,'
    #define INF_COMPILE_INFO   ''
    #define INF_SYNTAX_INFO    '2 1 1 -1 0 0 0'
    #define INF_BE_INFO        ''

// UNI (*.uni)
#define EDK2_UNI_LANGUAGE_ID   "edk2uni"
#define EDK2_UNI_LANGUAGE_NAME "EDK2 UNI"
    #define UNI_SETUP_INFO     'MN='EDK2_UNI_LANGUAGE_NAME',TABS=+2,MA=1 74 1,KEYTAB=ext-keys,WW=1,IWT=0,ST='0x0A',IN=2,WC=A-Za-z0-9_,LN='EDK2_UNI_LANGUAGE_NAME',CF=1,LNL=1,TL=0,BNDS=,'
    #define UNI_COMPILE_INFO   ''
    #define UNI_SYNTAX_INFO    '2 1 1 -1 0 0 0'
    #define UNI_BE_INFO        ''

// VFR (*.vfr, *.vfi)
#define EDK2_VFR_LANGUAGE_ID   "edk2vfr"
#define EDK2_VFR_LANGUAGE_NAME "EDK2 VFR"
    #define VFR_SETUP_INFO     'MN='EDK2_VFR_LANGUAGE_NAME',TABS=+2,MA=1 74 1,KEYTAB=ext-keys,WW=1,IWT=0,ST='0x0A',IN=2,WC=A-Za-z0-9_,LN='EDK2_VFR_LANGUAGE_NAME',CF=1,LNL=1,TL=0,BNDS=,'
    #define VFR_COMPILE_INFO   ''
    #define VFR_SYNTAX_INFO    '2 1 1 -1 0 0 0'
    #define VFR_BE_INFO        ''

//
// Patterns - UNIX regular expression
//
#define PATTERN_SECTION                  '^(\[.+\])'
#define PATTERN_GUID_PPI_PROTOCOL        '^\:b?([a-zA-Z0-9_]+)\:b*=\:b+\{'
#define PATTERN_PCD_TYPE_0               '^\:b?[a-zA-Z0-9_]+\.([a-zA-Z0-9_]+)\:b*\|'
#define PATTERN_IDF_IMAGE                '^\:b?#image\:b+([a-zA-Z0-9_]+)\:b'
#define PATTERN_UNI_STRING               '^\:b?#string\:b+([a-zA-Z0-9_]+)\:b'

//
// Add EDK2 languages and associate extensions, lexer
//
defload ()
{
    _str edk2_vlx = strip_filename (__PATH__, "N") :+ FILESEP :+ 'edk2.vlx';

    // Load lexer
    if (file_exists (edk2_vlx)) {
        import_lexer_file (edk2_vlx);
    } else {
        show (edk2_vlx);
        return;
    }

    // Create Language/Extension
    _CreateLanguage (EDK2_DEC_LANGUAGE_ID, EDK2_DEC_LANGUAGE_NAME, DEC_SETUP_INFO, DEC_COMPILE_INFO, DEC_SYNTAX_INFO, DEC_BE_INFO);
    _CreateExtension ('dec', EDK2_DEC_LANGUAGE_ID);

    _CreateLanguage (EDK2_DSC_LANGUAGE_ID, EDK2_DSC_LANGUAGE_NAME, DSC_SETUP_INFO, DSC_COMPILE_INFO, DSC_SYNTAX_INFO, DSC_BE_INFO);
    _CreateExtension ('dsc', EDK2_DSC_LANGUAGE_ID);
    _CreateExtension ('env', EDK2_DSC_LANGUAGE_ID);

    _CreateLanguage (EDK2_FDF_LANGUAGE_ID, EDK2_FDF_LANGUAGE_NAME, FDF_SETUP_INFO, FDF_COMPILE_INFO, FDF_SYNTAX_INFO, FDF_BE_INFO);
    _CreateExtension ('fdf', EDK2_FDF_LANGUAGE_ID);

    _CreateLanguage (EDK2_IDF_LANGUAGE_ID, EDK2_IDF_LANGUAGE_NAME, IDF_SETUP_INFO, IDF_COMPILE_INFO, IDF_SYNTAX_INFO, IDF_BE_INFO);
    _CreateExtension ('idf', EDK2_IDF_LANGUAGE_ID);

    _CreateLanguage (EDK2_INF_LANGUAGE_ID, EDK2_INF_LANGUAGE_NAME, INF_SETUP_INFO, INF_COMPILE_INFO, INF_SYNTAX_INFO, INF_BE_INFO);
    _CreateExtension ('inf', EDK2_INF_LANGUAGE_ID);

    _CreateLanguage (EDK2_UNI_LANGUAGE_ID, EDK2_UNI_LANGUAGE_NAME, UNI_SETUP_INFO, UNI_COMPILE_INFO, UNI_SYNTAX_INFO, UNI_BE_INFO);
    _CreateExtension ('uni', EDK2_UNI_LANGUAGE_ID);

    _CreateLanguage (EDK2_VFR_LANGUAGE_ID, EDK2_VFR_LANGUAGE_NAME, VFR_SETUP_INFO, VFR_COMPILE_INFO, VFR_SYNTAX_INFO, VFR_BE_INFO);
    _CreateExtension ('vfr', EDK2_VFR_LANGUAGE_ID);
    _CreateExtension ('vfi', EDK2_VFR_LANGUAGE_ID);

    return;
}

//
// Search matched pattern
//
int search_patterns (_str patterns, _str &proc_name, boolean find_first)
{
    if (find_first) {
        if (proc_name :== '') {
            proc_name = _clex_identifier_re ();
        }
        return search (patterns, '@uh');
    } else {
        return repeat_search ();
    }
}

//
// Tag matched "one" pattern on single line
//
boolean tag_pattern (_str current_line, _str pattern, _str &proc_name, _str tag_type)
{
    int start_num = 0;

    start_num = pos (pattern, current_line, 1, 'u');

    if (start_num != 0) {
        proc_name = tag_tree_compose_tag (
                        substr (current_line , pos ('S1'), pos ('1')),
                        "",
                        tag_type
                        );
        return true;
    }

    return false;
}

//
// Search/Tag for EDK2 DEC Language
//
int edk2dec_proc_search (_str &proc_name, boolean find_first)
{
    int status = 0;
    _str search_string = PATTERN_SECTION           :+ '|' :+
                         PATTERN_GUID_PPI_PROTOCOL :+ '|' :+
                         PATTERN_PCD_TYPE_0

    // Search
    status = search_patterns (search_string, proc_name, find_first);
    if (status) {
        proc_name = "";
        return status;
    }

    // Tag
    _str line = '';

    get_line (line);

    if (tag_pattern (line, PATTERN_SECTION,           proc_name, 'func')) return 0;
    if (tag_pattern (line, PATTERN_GUID_PPI_PROTOCOL, proc_name, 'gvar')) return 0;
    if (tag_pattern (line, PATTERN_PCD_TYPE_0,        proc_name, 'gvar')) return 0;

    return 0;
}

//
// Search/Tag for EDK2 DSC Language
//
int edk2dsc_proc_search (_str &proc_name, boolean find_first)
{
    int status = 0;
    _str search_string = PATTERN_SECTION :+ '|' :+
                         PATTERN_PCD_TYPE_0;

    // Search
    status = search_patterns (search_string, proc_name, find_first);

    if (status) {
        proc_name = "";
        return status;
    }

    // Tag
    _str line = '';

    get_line (line);

    if (tag_pattern (line, PATTERN_SECTION,    proc_name, 'func')) return 0;
    if (tag_pattern (line, PATTERN_PCD_TYPE_0, proc_name, 'gvar')) return 0;

    return 0;
}

//
// Search/Tag for EDK2 FDF Language
//
int edk2fdf_proc_search (_str &proc_name, boolean find_first)
{
    int status = 0;
    _str search_string = PATTERN_SECTION;

    // Search
    status = search_patterns (search_string, proc_name, find_first);
    if (status) {
        proc_name = "";
        return status;
    }

    // Tag
    _str line = '';

    get_line (line);

    if (tag_pattern (line, PATTERN_SECTION, proc_name, 'func')) return 0;

    return 0;
}

//
// Search/Tag for EDK2 IDF Language
//
int edk2idf_proc_search (_str &proc_name, boolean find_first)
{
    int status = 0;
    _str search_string = PATTERN_IDF_IMAGE;

    // Search
    status = search_patterns (search_string, proc_name, find_first);

    if (status) {
        proc_name = "";
        return status;
    }

    // Tag
    _str line = '';

    get_line (line);

    if (tag_pattern (line, PATTERN_IDF_IMAGE, proc_name, 'gvar')) return 0;

    return 0;
}

//
// Search/Tag for EDK2 INF Language
//
int edk2inf_proc_search (_str &proc_name, boolean find_first)
{
    int status = 0;
    _str search_string = PATTERN_SECTION;

    // Search
    status = search_patterns (search_string, proc_name, find_first);

    if (status) {
        proc_name = "";
        return status;
    }

    // Tag
    _str line = '';

    get_line (line);

    if (tag_pattern (line, PATTERN_SECTION, proc_name, 'func')) return 0;

    return 0;
}


//
// Search/Tag for EDK2 UNI Language
//
int edk2uni_proc_search (_str &proc_name, boolean find_first)
{
    int status = 0;
    _str search_string = PATTERN_UNI_STRING;

    // Search
    status = search_patterns (search_string, proc_name, find_first);

    if (status) {
        proc_name = "";
        return status;
    }

    // Tag
    _str line = '';

    get_line (line);

    if (tag_pattern (line, PATTERN_UNI_STRING, proc_name, 'gvar')) return 0;

    return 0;
}

//
// Search/Tag for EDK2 VFR Language
//
int edk2vfr_proc_search (_str &proc_name, boolean find_first)
{
    return 1;
}

