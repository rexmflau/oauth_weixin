# -*- coding: utf-8 -*-
from openerp import models, fields, api
import werkzeug.urls
import urlparse
from openerp import SUPERUSER_ID
from openerp.addons.web.controllers.main import set_cookie_and_redirect, login_and_redirect
import urllib2
import json
import openerp
import base64

class res_users(models.Model):
    _inherit = 'res.users'

    openid = fields.Char()
    access_token = fields.Char()
    refresh_token = fields.Char()
    unionid = fields.Char()
    sex = fields.Integer()

    @api.model
    def _get_token_data(self):
        weixin_auth_provider = self.env['weixin.auth.provider'].search([])[0]
        endpoint = weixin_auth_provider.validation_endpoint
        values = {'code': self._context['code']}
        values['appid'] = weixin_auth_provider.appid
        values['secret'] = weixin_auth_provider.secret
        values['grant_type'] = 'authorization_code'
        params = werkzeug.url_encode(values)
        url = endpoint + '?' + params
        f = urllib2.urlopen(url)
        response = f.read()
        return json.loads(response)

    @api.model
    def _weixin_get_userinfo(self, access_token, openid):
        weixin_auth_provider = self.env['weixin.auth.provider'].search([])[0]
        endpoint = weixin_auth_provider.data_endpoint
        values = {'access_token': access_token}
        values['openid'] = openid
        params = werkzeug.url_encode(values)
        url = endpoint + '?' + params
        f = urllib2.urlopen(url)
        response = f.read()
        return json.loads(response)
    @api.model
    def weixin_auth_signup(self):
        name = self._context['name']
        email = self._context['email']
        userinfo = self._weixin_get_userinfo(self._context['access_token'], self._context['openid'])
        user_id = self.search([('login', '=', 'templatesupplier')])[0].copy(default={'openid': userinfo['openid'],
                               'login': email,
                               'access_token': self._context['access_token'],
                               'refresh_token': self._context['refresh_token'],
                               'name': name,
                               'sex': userinfo['sex'],
                               'lang': userinfo['language'],
                               'zip': userinfo['province'],
                               'street': userinfo['country'],
                               'image': base64.b64encode(urllib2.urlopen(userinfo['headimgurl']).read()),
                               'unionid': userinfo['unionid']})
        return (self._context['state'], user_id.login, user_id.access_token)
    @api.model
    def weixin_auth_signin(self, token_data, user_ids):
        user_ids[0].write({'access_token': token_data['access_token'],
                            'refresh_token': token_data['refresh_token']})
        return (self._context['state'], user_ids[0].login, token_data['access_token'])
    @api.model
    def weixin_auth_oauth(self):
        code = self._context['code']
        token_data = self._get_token_data(code)
        if token_data.get("errcode"):
            raise Exception(token_data['errcode'])
        openid = token_data['openid']
        user_ids = self.search([("openid", "=", openid)])
        assert len(user_ids) == 1
        return user_ids, token_data
    def check_credentials(self, cr, uid, password):
        try:
            return super(res_users, self).check_credentials(cr, uid, password)
        except openerp.exceptions.AccessDenied:
            res = self.search(cr, SUPERUSER_ID, [('id', '=', uid), ('access_token', '=', password)])
            if not res:
                raise
