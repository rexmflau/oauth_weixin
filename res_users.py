# -*- coding: utf-8 -*-
from openerp import models, fields, api
import werkzeug.urls
import urlparse
from openerp import SUPERUSER_ID
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

    def _get_token_data(self, code):
        weixin_auth_provider = self.env['weixin.auth.provider'].search([])[0]
        endpoint = weixin_auth_provider.validation_endpoint
        values = {'code': code}
        values['appid'] = weixin_auth_provider.appid
        values['secret'] = weixin_auth_provider.secret
        values['grant_type'] = 'authorization_code'
        params = werkzeug.url_encode(values)
        url = endpoint + '?' + params
        f = urllib2.urlopen(url)
        response = f.read()
        return json.loads(response)

    def _weixin_get_userinfo(self, token_data):
        weixin_auth_provider = self.env['weixin.auth.provider'].search([])[0]
        endpoint = weixin_auth_provider.data_endpoint
        values = {'access_token': token_data['access_token']}
        values['openid'] = token_data['openid']
        params = werkzeug.url_encode(values)
        url = endpoint + '?' + params
        f = urllib2.urlopen(url)
        response = f.read()
        return json.loads(response)
    def _weixin_get_group(self):
        dataobj = self.env['ir.model.data']
        result = []
        try:
            dummy, group_id = dataobj.get_object_reference('base', 'group_user')
            result.append(group_id)
            dummy, group_id = dataobj.get_object_reference('base', 'group_no_one')
            result.append(group_id)
            dummy, group_id = dataobj.get_object_reference('base', 'group_portal')
            result.append(group_id)
        except ValueError:
            # If these groups does not exists anymore
            pass
        return result
    def weixin_auth_signin(self, token_data):
        try:
            openid = token_data['openid']
            user_ids = self.search([("openid", "=", openid)])
            if not user_ids:
                raise openerp.exceptions.AccessDenied()
            assert len(user_ids) == 1
            user_ids[0].write({'access_token': token_data['access_token'],
                               'refresh_token': token_data['refresh_token']})
            return user_ids[0].login
        except openerp.exceptions.AccessDenied:
            userinfo = self._weixin_get_userinfo(token_data)
            user_id = self.search([('login', '=', 'templatesupplier')])[0].copy(default={'openid': token_data['openid'],
                                   'login': token_data['openid'],
                                   'access_token': token_data['access_token'],
                                   'refresh_token': token_data['refresh_token'],
                                   'name': userinfo['nickname'],
                                   'sex': userinfo['sex'],
                                   'lang': userinfo['language'],
                                   'zip': userinfo['province'],
                                   'street': userinfo['country'],
                                   'image': base64.b64encode(urllib2.urlopen(userinfo['headimgurl']).read()),
                                   'unionid': userinfo['unionid']})
            return user_id.login
    @api.model
    def weixin_auth_oauth(self):
        code = self._context['code']
        token_data = self._get_token_data(code)
        if token_data.get("errcode"):
            raise Exception(token_data['errcode'])
        login = self.weixin_auth_signin(token_data)
        if not login:
            raise openerp.exceptions.AccessDenied()
        # return user credentials
        return (self._context['state'], login, token_data['access_token'])

    def check_credentials(self, cr, uid, password):
        try:
            return super(res_users, self).check_credentials(cr, uid, password)
        except openerp.exceptions.AccessDenied:
            res = self.search(cr, SUPERUSER_ID, [('id', '=', uid), ('access_token', '=', password)])
            if not res:
                raise