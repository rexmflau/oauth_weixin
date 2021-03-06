# -*- coding: utf-8 -*-
from openerp.http import request
from openerp import http
import json
from openerp.modules.registry import RegistryManager
from openerp import SUPERUSER_ID
import werkzeug.utils
from openerp.addons.web.controllers.main import db_monodb, ensure_db, set_cookie_and_redirect, login_and_redirect
import logging
import openerp
from openerp.addons.web.controllers.main import Home
from openerp.tools.translate import _

_logger = logging.getLogger(__name__)

class OAuthLogin(Home):
    @http.route()
    def web_login(self, *args, **kw):
        #if 'login' in kw and 'password' in kw:
        #    return super(OAuthLogin, self).web_login(*args, **kw)
        #return werkzeug.utils.redirect('/weixin/login', 303)
        return super(OAuthLogin, self).web_login(*args, **kw)

class weixin(http.Controller):
    @http.route('/baoshunkeji.com.html', auth='public')
    def wosign(self, **kw):
        return werkzeug.url_encode({'a':'a','b':'b'})
        #return 'VATd4tAahG22n07h1fbXghJg7pD9iIOvDq5bNBYT8fw='
    @http.route('/weixin/login', auth='public', website=True)
    def weixin_login(self, **kw):
        weixin_auth_provider = request.registry.get('weixin.auth.provider')
        value = weixin_auth_provider.read(request.cr, SUPERUSER_ID, [1])[0]
        value['dbname'] = request.db
        return request.render('oauth_weixin.login', value)
    @http.route('/weixin/name_email', auth='public', website=True)
    def weixin_name_email(self, **kw):
        qcontext = request.params.copy()
        if kw.get('email') and kw.get('name'):
            import re
            def validateEmail(email):
                if email:
                    if len(email) > 7:
                        if re.match("^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3})(\\]?)$", email) != None:
                            return 1
                return 0
            if not validateEmail(kw['email']) or kw['name'] == '':
                qcontext['error'] = _('name or email error')
        if 'error' not in qcontext and kw.get('state') and kw.get('access_token') and kw.get('name') and kw.get('email'):
            dbname = kw['state']
            registry = RegistryManager.get(dbname)
            u = registry.get('res.users')
            with registry.cursor() as cr:
                try:
                    credentials = u.weixin_auth_signup(cr, SUPERUSER_ID, kw)
                    url='/web'
                    cr.commit()
                    return login_and_redirect(*credentials, redirect_url=url)
                except Exception, e:
                    _logger.exception("OAuth2: %s" % str(e))
                    url = "/weixin/login?oauth_error=2"
            return set_cookie_and_redirect(url)
        return request.render('oauth_weixin.name_email', qcontext)
    @http.route('/weixin/signin', auth='public', website=True)
    def weixin_signin(self, **kw):
        #https://baoshunkeji.com/weixin/signin?code=0015b3203e9151b79c93fa46ea0d9aeo&state=test
        dbname = kw['state']
        registry = RegistryManager.get(dbname)
        with registry.cursor() as cr:
            try:
                u = registry.get('res.users')
                user_ids, token_data = u.weixin_auth_oauth(cr, SUPERUSER_ID, kw)
                if user_ids:
                    assert len(user_ids) == 1
                    credentials = u.weixin_auth_signin(cr, SUPERUSER_ID, token_data, user_ids, kw)
                else:
                    json_token_data = {'openid': token_data['openid'],
                                       'refresh_token': token_data['refresh_token'],
                                       'access_token': token_data['access_token']}
                    url = "/weixin/name_email?" + werkzeug.url_encode(json_token_data) + '&state=' + kw['state']
                    return set_cookie_and_redirect(url)
                cr.commit()
                url='/web'
                return login_and_redirect(*credentials, redirect_url=url)
            except Exception, e:
                # signup error
                _logger.exception("OAuth2: %s" % str(e))
                url = "/weixin/login?oauth_error=2"

        return set_cookie_and_redirect(url)
