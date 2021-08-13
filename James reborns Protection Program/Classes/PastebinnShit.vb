Imports System.Collections.Specialized
Imports System.Net
Imports System.Text

Public Class Paste

    Dim _devkey As String
    Dim _username As String
    Dim _userpassword As String
    Dim _PasteCode As String
    Dim _PasteName As String
    Dim _Syntax As String
    Dim _ExpireDate As String
    Dim _PasteExposure As Integer
    Dim ukey As String
    Sub New(ByVal Key As String, ByVal username As String, ByVal password As String, ByVal PasteCode As String, _
            ByVal PasteName As String, ByVal PasteExposure As Integer, ByVal SyntaxHighlighting As String, _
            ByVal ExpireDate As String)
        _devkey = Key
        _username = username
        _userpassword = password
        _PasteCode = PasteCode
        _PasteName = PasteName
        _PasteExposure = PasteExposure
        _Syntax = SyntaxHighlighting
        _ExpireDate = ExpireDate
    End Sub

    Public Function Start() As String
        Dim chiavi As New NameValueCollection()
        chiavi.Add("api_dev_key", _devkey)
        chiavi.Add("api_user_name", _username)
        chiavi.Add("api_user_password", _userpassword)

        Dim wClient As New WebClient()
        Dim risposta As String = Encoding.UTF8.GetString(wClient.UploadValues("https://pastebin.com/api/api_login.php", chiavi))

        If risposta.ToLower.Contains("bad api request") Then
            MessageBox.Show("Login failed!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error)
            Return "ERROR"
        Else
            ukey = risposta
            Try
                Dim output As String = MakePaste() 'Restituisce una stringa
                Process.Start(output)
                Return "SUCCESS"
            Catch Ex As Exception
                MessageBox.Show("Exception: " & Ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error)
                Return "ERROR"
            End Try
        End If
    End Function

    Public Function MakePaste() As String
        If ukey = "" Then Return "ERROR"

        Dim chiavi As New NameValueCollection()
        chiavi.Add("api_dev_key", _devkey)
        chiavi.Add("api_user_key", ukey)
        chiavi.Add("api_option", "paste")
        chiavi.Add("api_paste_code", _PasteCode)
        chiavi.Add("api_paste_name", _PasteName)
        chiavi.Add("api_paste_format", _Syntax)
        chiavi.Add("api_paste_private", _PasteExposure)
        chiavi.Add("api_paste_expire_date", "N")

        Dim wc As New WebClient()
        Dim Risultato As String = ""
        Dim Risposta As String = Encoding.UTF8.GetString(wc.UploadValues( _
                                                         "https://pastebin.com/api/api_post.php", chiavi))

        If Risposta.ToLower.Contains("bad api request") Then
            ' Key non valida
        Else
            Risultato = Risposta
        End If
        Return Risultato
    End Function
End Class