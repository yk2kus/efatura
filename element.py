#!/usr/bin/python
 
from suds.sax.element import Element
WssToken = Element('wss:UsernameToken') 
WssSecurity = Element('wss:Security').setText('xmlns:wss="http://schemas.xmlsoap.org/ws/2002/12/secext"')
reqsoapheader = Element('S:Header') # create the parent element
WssUsernameToken = Element('wss:UsernameToken')
WssUsername = Element('wss:Username').setText('599999993/37')
WssPassword = Element('wss:Password').setText('ikCyRV+SWfvZ5c6Q0bhrBQ==')
WssNonce = Element('wss:Nonce').setText('''fkAHne7cqurxpImCfBC8EEc2vskyUyNofWi0ptIijYg4gYCxir++unzfPVPpusloEtmLkcZjf+E6
	T9/76tsCqdupUkxOhWtkRH5IrNwmfEW1ZGFQgYTF21iyKBRzMdsJMhhHrofYYV/YhSPdT4dlgG0t
	k9Z736jFuw061mP2TNqHcR/mQR0yW/AEOC6RPumqO8OAfc9/b4KFBSfbpY9HRzbD8bKiTo20n0Pt
	amZevCSVHht4yt/Xwgd+KV70WFzyesGVMOgFRTWZyXyXBVaBrkJS8b6PojxADLcpWRnw5+YeOs3c
	PU2o1H/YgAam1QuEHioCT2YTdRt+9p6ARNElFg==''')
WssCreated = Element('wss:Created').setText('>YEWoIoqIY5DOD11SeXz+0i4b/AJg1/RgNcOHOYpSxGk')
WssSecurity.children = [WssUsernameToken]
reqsoapheader.children = [WssSecurity]
WssUsernameToken.children = [WssUsername, WssPassword, WssNonce,WssCreated]

print reqsoapheader

"""
<S:Header>
<wss:Security xmlns:wss="Createdhttp://schemas.xmlsoap.org/ws/2002/12/secext">
	<wss:UsernameToken>
	<wss:Username>599999993/37</wss:Username>
	<wss:Password>ikCyRV+SWfvZ5c6Q0bhrBQ==</wss:Password>
	<wss:Nonce>
	fkAHne7cqurxpImCfBC8EEc2vskyUyNofWi0ptIijYg4gYCxir++unzfPVPpusloEtmLkcZjf+E6
	T9/76tsCqdupUkxOhWtkRH5IrNwmfEW1ZGFQgYTF21iyKBRzMdsJMhhHrofYYV/YhSPdT4dlgG0t
	k9Z736jFuw061mP2TNqHcR/mQR0yW/AEOC6RPumqO8OAfc9/b4KFBSfbpY9HRzbD8bKiTo20n0Pt
	amZevCSVHht4yt/Xwgd+KV70WFzyesGVMOgFRTWZyXyXBVaBrkJS8b6PojxADLcpWRnw5+YeOs3c
	PU2o1H/YgAam1QuEHioCT2YTdRt+9p6ARNElFg==
	</wss:Nonce>
	<wss:>>YEWoIoqIY5DOD11SeXz+0i4b/AJg1/RgNcOHOYpSxGk</wss:Created>
	</wss:UsernameToken>
</wss:Security>
</S:Header>
"""
