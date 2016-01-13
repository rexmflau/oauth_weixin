# -*- coding: utf-8 -*-
from openerp import models, fields

class weixin_auth_provider(models.Model):
    _name = 'weixin.auth.provider'

    name = fields.Char('Provider name', required=True)
    appid = fields.Char('appid')
    auth_endpoint = fields.Char('Authentication URL', required=True)
    scope = fields.Char('Scope')
    secret = fields.Char()
    redirect_uri = fields.Char()
    validation_endpoint = fields.Char('Validation URL', required=True)
    data_endpoint = fields.Char('Data URL')
    enabled = fields.Boolean('Allowed')
    css_class = fields.Char('CSS class')
    body = fields.Char('Body', required=True)
    sequence = fields.Integer()
