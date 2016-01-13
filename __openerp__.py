# -*- coding: utf-8 -*-
{
    'name': 'oauth_weixin',
    'version': '0.1',
    'category': 'Tools',
    'description': """
oauth_weixin
""",
    'author': 'lipeng',
    'website': 'https://www.ylnlp.com',
    'summary': 'oauth_weixin',
    'data': [
        'views/auth_weixin_login.xml',
        'weixin_auth_data.xml',
    ],
    'depends': ['base', 'website'],
    'sequence': 0,
    'installable': True,
    'application': True,
    'auto_install': False,
}