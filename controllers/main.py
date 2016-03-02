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
        return 'VATd4tAahG22n07h1fbXghJg7pD9iIOvDq5bNBYT8fw='
    @http.route('/weixin/login', auth='public', website=True)
    def weixin_login(self, **kw):
        weixin_auth_provider = request.registry.get('weixin.auth.provider')
        value = weixin_auth_provider.read(request.cr, SUPERUSER_ID, [1])[0]
        value['dbname'] = request.db
        return request.render('oauth_weixin.login', value)
    @http.route('/weixin/name_email', auth='public', website=True)
    def weixin_name_email(self, **kw):
        qcontext = request.params.copy()
        if kw.get('email'):
            import re
            def validateEmail(email):
                if email:
                    if len(email) > 7:
                        if re.match("^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3})(\\]?)$", email) != None:
                            return 1
                return 0
            if not validateEmail(kw['email']):
                qcontext['error'] = _('email error')
        if 'error' not in qcontext and kw.get('state') and kw.get('code') and kw.get('name') and kw.get('email'):
            dbname = kw['state']
            registry = RegistryManager.get(dbname)
            u = registry.get('res.users')
            with registry.cursor() as cr:
                try:
                    credentials = u.weixin_auth_signup(cr, SUPERUSER_ID, kw)
                    url='/web'
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
                credentials = u.weixin_auth_oauth(cr, SUPERUSER_ID, kw)
                cr.commit()
                url='/web'
                return login_and_redirect(*credentials, redirect_url=url)
            except AttributeError:
                # auth_signup is not installed
                _logger.error("auth_signup not installed on database %s: oauth sign up cancelled." % (dbname,))
                url = "/weixin/login?oauth_error=1"
            except Exception, e:
                # signup error
                _logger.exception("OAuth2: %s" % str(e))
                url = "/weixin/login?oauth_error=2"

        return set_cookie_and_redirect(url)
