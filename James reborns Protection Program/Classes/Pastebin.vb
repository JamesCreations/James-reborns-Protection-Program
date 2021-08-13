Option Strict On
Option Explicit On
Imports System.Net
Imports System.Text.RegularExpressions
Imports System.Xml
Imports System.IO
Imports System.Text
Imports System.Net.NetworkInformation

Public Class Pastebin
#Region "POST req function"
    Private Shared cookie As New CookieContainer
    Public Shared Function Postreq(ByVal Url As String, ByVal post As String) As String
        Dim request As HttpWebRequest
        request = CType(HttpWebRequest.Create(Url), HttpWebRequest)
        request.Method = WebRequestMethods.Http.Post
        request.CookieContainer = cookie
        request.UserAgent = "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0"
        request.ContentType = "application/x-www-form-urlencoded"
        Dim byteArr() As Byte = Encoding.Default.GetBytes(post)
        request.ContentLength = byteArr.Length
        Dim dataStream As Stream = request.GetRequestStream()
        dataStream.Write(byteArr, 0, byteArr.Length)
        Dim response As HttpWebResponse
        response = CType(request.GetResponse(), HttpWebResponse)
        Return New StreamReader(response.GetResponseStream()).ReadToEnd()
    End Function
#End Region
    Private Shared Property dev_key As String = My.Forms.JamesrebornsProtections.TextBox177.Text 'Your dev-key
    Public Shared Property Username As String 'Property "Username" - must be setted first
    Public Shared Property Password As String 'Property "Password" - must be setted first
    ''' <summary>
    ''' Returns the UserAPIKey, also know as session key
    ''' </summary>
    ''' <returns></returns>
    ''' <remarks></remarks>
    Public Shared Function GetUserAPIKey() As String
        If String.IsNullOrEmpty(Username) OrElse String.IsNullOrEmpty(Password) Then
            Return "False"
            Exit Function
        End If
        Dim post As String = "api_dev_key=" & dev_key & "&api_user_name=" & Username & "&api_user_password=" & Password
        Dim url As String = "http://pastebin.com/api/api_login.php"
        Dim UserAPIKey As String = CStr(Postreq(url, post))
        Return UserAPIKey
    End Function
    Public Structure UserInformations
        Dim Username As String
        Dim UserFormat As String
        Dim UserExpiration As String
        Dim AvatarUrl As Uri
        Dim UserPrivate As String
        Dim UserEmail As String
        Dim UserWebsite As Uri
        Dim UserLocation As String
        Dim UserIsPro As Boolean
    End Structure
    ''' <summary>
    ''' Function to get Userinformations
    ''' </summary>
    ''' <returns>Specific Userinformations</returns>
    ''' <remarks></remarks>
    Public Shared Function GetUserInformations() As UserInformations
        Dim Info As New UserInformations
        Dim UserAPIKey As String = GetUserAPIKey()
        Dim post As String = "api_option=userdetails&api_user_key=" & UserAPIKey & "&api_dev_key=" & dev_key
        Dim Url As String = "http://pastebin.com/api/api_post.php"
        Dim html As String = CStr(Postreq(Url, post))
        Using reader As XmlReader = XmlReader.Create(New StringReader(html))
            With New StringBuilder

                reader.ReadToFollowing("user_format_short")
                Info.UserFormat = reader.ReadElementContentAsString()
                reader.ReadToFollowing("user_expiration")
                Dim exp As String = reader.ReadElementContentAsString()
                Select Case exp
                    Case CStr(exp = "N")
                        exp = "Never"
                        Info.UserExpiration = exp
                    Case Else
                        Info.UserExpiration = exp
                End Select
                '      Info.UserExpiration = exp
                reader.ReadToFollowing("user_avatar_url")
                Info.AvatarUrl = New Uri(reader.ReadElementContentAsString)
                reader.ReadToFollowing("user_private")
                Dim private_ As String = reader.ReadElementContentAsString
                Select Case private_
                    Case "0"
                        private_ = "Public"
                        Info.UserPrivate = private_
                    Case "1"
                        private_ = "Unlisted"
                        Info.UserPrivate = private_
                    Case "2"
                        private_ = "Private"
                        Info.UserPrivate = private_
                End Select
                reader.ReadToFollowing("user_website")
                Dim Website_s As String = reader.ReadElementContentAsString
                If Not String.IsNullOrEmpty(Website_s) Then
                    Dim Website As Uri = New Uri(reader.ReadElementContentAsString)
                    Info.UserWebsite = Website
                End If
                reader.ReadToFollowing("user_email")
                Info.UserEmail = reader.ReadElementContentAsString
                reader.ReadToFollowing("user_location")
                Info.UserLocation = reader.ReadElementContentAsString
                reader.ReadToFollowing("user_account_type")
                Dim UserIsPro_s As String = reader.ReadElementContentAsString
                Dim UserIsPro As Boolean
                Select Case UserIsPro_s
                    Case "0"
                        UserIsPro = False
                    Case "1"
                        UserIsPro = True
                End Select
                Info.UserIsPro = UserIsPro
            End With
        End Using
        Return Info
    End Function
    Public Enum syntax
        sixfivenulltwoacme = 0
        sixfivenulltwokickass = 1
        sixfivenulltwotasm = 2
        abap = 3
        actionscript = 4
        actionscript3 = 5
        ada = 6
        algol68 = 7
        apache = 8
        applescript = 9
        apt_sources = 10
        arm = 11
        asm = 12
        asp = 13
        asymptote = 14
        autoconf = 15
        autohotkey = 16
        autoit = 17
        avisynth = 18
        awk = 19
        bascomavr = 20
        bash = 21
        basic4gl = 22
        bibtex = 23
        blitzbasic = 24
        bnf = 25
        boo = 26
        bf = 27
        c = 28
        c_mac = 29
        cil = 30
        csharp = 31
        cpp = 32
        cpp_qt = 33
        c_loadrunner = 34
        caddcl = 35
        cadlisp = 36
        cfdg = 37
        chaiscript = 38
        clojure = 39
        klonec = 40
        klonecpp = 41
        cmake = 42
        cobol = 43
        coffeescript = 44
        cfm = 45
        css = 46
        cuesheet = 47
        d = 48
        dcl = 49
        dcpu16 = 50
        dcs = 51
        delphi = 52
        oxygene = 53
        diff = 54
        div = 55
        dos = 56
        dot = 57
        e = 58
        ecmascript = 59
        eiffel = 60
        email = 61
        epc = 62
        erlang = 63
        fsharp = 64
        falcon = 65
        fo = 66
        f1 = 67
        fortran = 68
        freebasic = 69
        freeswitch = 70
        gambas = 71
        gml = 72
        gdb = 73
        genero = 74
        genie = 75
        gettext = 76
        go = 77
        groovy = 78
        gwbasic = 79
        haskell = 80
        haxe = 81
        hicest = 82
        hq9plus = 83
        html4strict = 84
        html5 = 85
        icon = 86
        idl = 87
        ini = 88
        inno = 89
        intercal = 90
        io = 91
        j = 92
        java = 93
        java5 = 94
        javascript = 95
        jquery = 96
        kixtart = 97
        latex = 98
        ldif = 99
        lb = 100
        lsl2 = 101
        lisp = 102
        llvm = 103
        locobasic = 104
        logtalk = 105
        lolcode = 106
        lotusformulas = 107
        lotusscript = 108
        lscript = 109
        lua = 110
        m68k = 111
        magiksf = 112
        make = 113
        mapbasic = 114
        matlab = 115
        mirc = 116
        mmix = 117
        modula2 = 118
        modula3 = 119
        mpasm = 121
        mxml = 122
        mysql = 123
        nagios = 124
        newlisp = 125
        text = 126
        nsis = 127
        oberon2 = 128
        objeck = 129
        objc = 130
        octave = 133
        pf = 134
        glsl = 135
        oobas = 136
        oracle11 = 137
        oracle8 = 138
        oz = 139
        parasail = 140
        parigp = 141
        pascal = 142
        pawn = 143
        pcre = 144
        per = 145
        perl = 146
        perl6 = 147
        php = 148
        php_brief = 149
        pic16 = 150
        pike = 151
        pixelbender = 152
        plsql = 153
        postgresql = 154
        povray = 155
        powershell = 156
        powerbuilder = 157
        proftpd = 158
        progress = 159
        prolog = 160
        properties = 161
        providex = 162
        purebasic = 163
        pycon = 164
        python = 165
        pys60 = 166
        q = 167
        qbasic = 168
        rsplus = 169
        rails = 170
        rebol = 171
        reg = 172
        rexx = 173
        robots = 174
        rpmspec = 175
        ruby = 176
        gnuplot = 177
        sas = 178
        scala = 179
        scheme = 180
        scilab = 181
        sdlbasic = 182
        smalltalk = 183
        smarty = 184
        spark = 185
        sparql = 186
        sql = 187
        stonescript = 188
        systemverilog = 189
        tsql = 190
        tcl = 191
        teraterm = 192
        thinbasic = 193
        typoscript = 194
        unicon = 195
        uscript = 196
        ups = 197
        urbi = 198
        vala = 199
        vbnet = 200
        vedit = 201
        verilog = 202
        vhdl = 203
        vim = 204
        visualprolog = 205
        vb = 206
        visualfoxpro = 207
        whitespace = 208
        whois = 209
        winbatch = 210
        xbasic = 211
        xml = 212
        xorg_conf = 213
        xpp = 214
        yaml = 215
        z80 = 216
        zxbasic = 217
    End Enum

    Private Shared Function getSyntax(ByVal s As syntax) As String
        Dim Syntax As String = s.ToString
        Select Case Syntax
            Case Is = "sixfivenulltwoacme"
                Syntax = "6502acme"
                Return Syntax
            Case Is = "sixfivenulltwokickass"
                Syntax = "6502kickass"
                Return Syntax
            Case Is = "sixfivenulltwotasm"
                Syntax = "6502tasm"
                Return Syntax
            Case Is = "cpp_qt"
                Syntax = "cpp-qt"
                Return Syntax
            Case Is = "php_brief"
                Syntax = "php-brief"
                Return Syntax
            Case Else
                Return Syntax
        End Select
    End Function
    Public Enum PasteExpire
        Never = 0
        ten_minutes = 1
        one_hour = 2
        one_day = 3
        one_week = 4
        two_weeks = 5
        one_month = 6
    End Enum
    Private Shared Function getPasteExpire(ByVal s As PasteExpire) As String
        Select Case s
            Case CType(s = PasteExpire.Never, PasteExpire)
                Return "N"
            Case CType(s = PasteExpire.one_day, PasteExpire)
                Return "1D"
            Case CType(s = PasteExpire.one_hour, PasteExpire)
                Return "1H"
            Case CType(s = PasteExpire.one_month, PasteExpire)
                Return "1M"
            Case CType(s = PasteExpire.one_week, PasteExpire)
                Return "1W"
            Case CType(s = PasteExpire.ten_minutes, PasteExpire)
                Return "10M"
            Case CType(s = PasteExpire.two_weeks, PasteExpire)
                Return "2W"
            Case Else
                Return Nothing
        End Select
    End Function
    Public Enum Privacy
        PublicPaste
        UnlistedPaste
        PrivatePaste
    End Enum
    Private Shared Function getPrivacy(ByVal s As Privacy) As String
        Select Case s.ToString
            Case "PrivatePaste"
                Return "2"
            Case "PublicPaste"
                Return "0"
            Case "UnlistedPaste"
                Return "1"
            Case Else
        End Select
    End Function
    ''' <summary>
    ''' Pastes a Text and returns the URL
    ''' </summary>
    ''' <param name="Title">Your title</param>
    ''' <param name="Text">Your text</param>
    ''' <param name="useLogin">UseLogin or Pasteanonymous</param>
    ''' <param name="syntax">The syntaxhighliting</param>
    ''' <param name="expire">The expiredate</param>
    ''' <param name="privacy">the privacy settings</param>
    ''' <returns></returns>
    ''' <remarks></remarks>
    Public Shared Function Paste(ByVal Title As String, ByVal Text As String, ByVal useLogin As Boolean, ByVal syntax As syntax, ByVal expire As PasteExpire, ByVal privacy As Privacy) As Uri
        Dim Syntax_ As String
        Dim Expire_ As String
        Dim Privacy_ As String
        Dim UserAPIKey As String = GetUserAPIKey()
        If useLogin = False AndAlso privacy = Pastebin.Privacy.PrivatePaste Then
            Return Nothing
            Exit Function
        End If
        Syntax_ = getSyntax(syntax)
        Expire_ = getPasteExpire(expire)
        Privacy_ = getPrivacy(privacy)
        If String.IsNullOrEmpty(Text) Then
            Return Nothing
            Exit Function
        End If
        Dim Post As String = "api_option=paste&api_user_key=" & UserAPIKey & "&api_paste_private=" & Privacy_ & "&api_paste_name=" & Title & "&api_paste_expire_date=" & Expire_ & "&papi_paste_format.=" & Syntax_ & "&api_dev_key=" & dev_key & "&api_paste_code=" & Text
        Dim URL As String = "http://pastebin.com/api/api_post.php"
        Dim ReturnLink As String = CStr(Postreq(URL, Post))
        Dim ReturnUri As Uri = New Uri(ReturnLink)
        If ReturnUri IsNot Nothing Then
            Return ReturnUri
        End If
    End Function
    ''' <summary>
    ''' The structure "pastes"
    ''' </summary>
    ''' <remarks></remarks>
    Public Structure Pastes
        Dim PasteKey As List(Of String)
        Dim PasteDate As List(Of Integer)
        Dim PasteTitle As List(Of String)
        Dim PasteSize As List(Of Integer)
        Dim PasteExpireDate As List(Of Integer)
        Dim PasteIsPrivate As List(Of Boolean)
        Dim PasteFormat As List(Of String)
        Dim PasteUrl As List(Of Uri)
        Dim PasteHits As List(Of Integer)
    End Structure
    ''' <summary>
    ''' Returns a List of your Pastes
    ''' </summary>
    ''' <returns>Specific List's</returns>
    ''' <remarks></remarks>
    Public Shared Function getUserPastes(ByVal Limit As Integer) As Pastes
        Dim PasteKey As New List(Of String)
        Dim PasteDate As New List(Of Integer)
        Dim PasteTitle As New List(Of String)
        Dim PasteSize As New List(Of Integer)
        Dim PasteExpireDate As New List(Of Integer)
        Dim PasteIsPrivate As New List(Of Boolean)
        Dim PasteFormat As New List(Of String)
        Dim PasteUrl As New List(Of Uri)
        Dim PasteHits As New List(Of Integer)
        Dim UserAPIKey As String = GetUserAPIKey()
        Dim post As String = "api_option=list&api_user_key=" & UserAPIKey & "&api_dev_key=" & dev_key & "&api_results_limit=" & Limit.ToString
        Dim html As String = Postreq("http://pastebin.com/api/api_post.php", post)
        For Each m As Match In New Regex("<paste_key>(.+)</paste_key>").Matches(html)
            PasteKey.Add(m.Groups.Item(1).Value)
        Next
        For Each m As Match In New Regex("<paste_date>(.+)</paste_date>").Matches(html)
            PasteDate.Add(Integer.Parse(m.Groups.Item(1).Value))
        Next
        For Each m As Match In New Regex("<paste_title>(.+)</paste_title>").Matches(html)
            PasteTitle.Add(m.Groups.Item(1).Value)
        Next
        For Each m As Match In New Regex("<paste_size>(.+)</paste_size>").Matches(html)
            PasteSize.Add(Integer.Parse(m.Groups.Item(1).Value))
        Next
        For Each m As Match In New Regex("<paste_expire_date>(.+)</paste_expire_date>").Matches(html)
            PasteExpireDate.Add(Integer.Parse(m.Groups.Item(1).Value))
        Next
        For Each m As Match In New Regex("<paste_private>(.+)</paste_private>").Matches(html)
            If m.Groups.Item(1).Value = "0" Then
                PasteIsPrivate.Add(False)
            Else
                PasteIsPrivate.Add(True)
            End If
        Next
        For Each m As Match In New Regex("<paste_format_long>(.+)</paste_format_long>").Matches(html)
            PasteFormat.Add(m.Groups.Item(1).Value)
        Next
        For Each m As Match In New Regex("<paste_url>(.+)</paste_url>").Matches(html)
            PasteUrl.Add(New Uri(m.Groups.Item(1).Value))
        Next
        For Each m As Match In New Regex("<paste_hits>(.+)</paste_hits>").Matches(html)
            PasteHits.Add(Integer.Parse(m.Groups.Item(1).Value))
        Next
        Dim Paste As New Pastes
        Paste.PasteDate = PasteDate
        Paste.PasteExpireDate = PasteExpireDate
        Paste.PasteFormat = PasteFormat
        Paste.PasteHits = PasteHits
        Paste.PasteIsPrivate = PasteIsPrivate
        Paste.PasteKey = PasteKey
        Paste.PasteSize = PasteSize
        Paste.PasteTitle = PasteTitle
        Paste.PasteUrl = PasteUrl
        Return Paste
    End Function
    ''' <summary>
    ''' Returns a List of Trending Pastes
    ''' </summary>
    ''' <returns>Specific List's</returns>
    ''' <remarks></remarks>
    Public Shared Function getTrandingPastes() As Pastes
        Dim post As String = "api_option=trends&api_dev_key=" & dev_key
        Dim PasteKey As New List(Of String)
        Dim PasteDate As New List(Of Integer)
        Dim PasteTitle As New List(Of String)
        Dim PasteSize As New List(Of Integer)
        Dim PasteExpireDate As New List(Of Integer)
        Dim PasteIsPrivate As New List(Of Boolean)
        Dim PasteFormat As New List(Of String)
        Dim PasteUrl As New List(Of Uri)
        Dim PasteHits As New List(Of Integer)
        Dim html As String = Postreq("http://pastebin.com/api/api_post.php", post)
        For Each m As Match In New Regex("<paste_key>(.+)</paste_key>").Matches(html)
            PasteKey.Add(m.Groups.Item(1).Value)
        Next
        For Each m As Match In New Regex("<paste_date>(.+)</paste_date>").Matches(html)
            PasteDate.Add(Integer.Parse(m.Groups.Item(1).Value))
        Next
        For Each m As Match In New Regex("<paste_title>(.+)</paste_title>").Matches(html)
            PasteTitle.Add(m.Groups.Item(1).Value)
        Next
        For Each m As Match In New Regex("<paste_size>(.+)</paste_size>").Matches(html)
            PasteSize.Add(Integer.Parse(m.Groups.Item(1).Value))
        Next
        For Each m As Match In New Regex("<paste_expire_date>(.+)</paste_expire_date>").Matches(html)
            PasteExpireDate.Add(Integer.Parse(m.Groups.Item(1).Value))
        Next
        For Each m As Match In New Regex("<paste_private>(.+)</paste_private>").Matches(html)
            If m.Groups.Item(1).Value = "0" Then
                PasteIsPrivate.Add(False)
            Else
                PasteIsPrivate.Add(True)
            End If
        Next
        For Each m As Match In New Regex("<paste_format_long>(.+)</paste_format_long>").Matches(html)
            PasteFormat.Add(m.Groups.Item(1).Value)
        Next
        For Each m As Match In New Regex("<paste_url>(.+)</paste_url>").Matches(html)
            PasteUrl.Add(New Uri(m.Groups.Item(1).Value))
        Next
        For Each m As Match In New Regex("<paste_hits>(.+)</paste_hits>").Matches(html)
            PasteHits.Add(Integer.Parse(m.Groups.Item(1).Value))
        Next
        Dim Paste As New Pastes
        Paste.PasteDate = PasteDate
        Paste.PasteExpireDate = PasteExpireDate
        Paste.PasteFormat = PasteFormat
        Paste.PasteHits = PasteHits
        Paste.PasteIsPrivate = PasteIsPrivate
        Paste.PasteKey = PasteKey
        Paste.PasteSize = PasteSize
        Paste.PasteTitle = PasteTitle
        Paste.PasteUrl = PasteUrl
        Return Paste
    End Function
    ''' <summary>
    ''' Deletes a paste
    ''' </summary>
    ''' <param name="PasteKey">The pastekey</param>
    ''' <returns></returns>
    ''' <remarks></remarks>
    Public Shared Function DeletePaste(ByVal PasteKey As String) As Boolean
        Dim URL As String = "http://pastebin.com/api/api_post.php"
        Dim APIUserKey As String = GetUserAPIKey()
        Dim post As String = "api_option=delete&api_user_key=" & APIUserKey & "&api_dev_key=" & dev_key & "&api_paste_key=" & PasteKey
        Dim html As String = Postreq(URL, post)
        If html.Contains("Paste Removed") Then
            Return True
        Else
            Return False
        End If
    End Function
    ''' <summary>
    ''' Returns the RAW data from a paste
    ''' </summary>
    ''' <param name="PasteKey">Your pastekey</param>
    ''' <returns></returns>
    ''' <remarks></remarks>
    Public Shared Function GetPasteText(ByVal PasteKey As String) As String
        With New WebClient
            Dim html As String = .DownloadString("http://pastebin.com/raw.php?i=" & PasteKey)
            Return html
        End With
    End Function
End Class
