import urllib
import pandas as pd
import datetime
from dateutil.parser import parse

from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseServerError

from sampleAppOAuth2 import getDiscoveryDocument
from sampleAppOAuth2.services import (
    getCustomerBalance,
    getBearerTokenFromRefreshToken,
    getUserProfile,
    getBearerToken,
    getSecretKey,
    validateJWTToken,
    revokeToken,
)

from sampleAppOAuth2.models import Base, CustomerBalance, UpdateLog
from django.conf import settings
from sqlalchemy.orm import sessionmaker

# Initiate SQLAlchemy
Session = sessionmaker(bind=settings.DB_ENGINE)
Base.metadata.create_all(settings.DB_ENGINE)
# TODO: session should only be initiated once - sqlAlchemy incompatible with Django
#  update code to use Django ORM for operations in a separate branch

def index(request):
    return render(request, 'index.html')


def connectToQuickbooks(request):
    url = getDiscoveryDocument.auth_endpoint
    params = {'scope': settings.ACCOUNTING_SCOPE, 'redirect_uri': settings.REDIRECT_URI,
              'response_type': 'code', 'state': get_CSRF_token(request), 'client_id': settings.CLIENT_ID}
    url += '?' + urllib.parse.urlencode(params)
    return redirect(url)


def signInWithIntuit(request):
    url = getDiscoveryDocument.auth_endpoint
    scope = ' '.join(settings.OPENID_SCOPES)  # Scopes are required to be sent delimited by a space
    params = {'scope': scope, 'redirect_uri': settings.REDIRECT_URI,
              'response_type': 'code', 'state': get_CSRF_token(request), 'client_id': settings.CLIENT_ID}
    url += '?' + urllib.parse.urlencode(params)
    return redirect(url)


def authCodeHandler(request):
    state = request.GET.get('state', None)
    error = request.GET.get('error', None)
    if error == 'access_denied':
        return redirect('sampleAppOAuth2:index')
    if state is None:
        return HttpResponseBadRequest()
    elif state != get_CSRF_token(request):  # validate against CSRF attacks
        return HttpResponse('unauthorized', status=401)

    auth_code = request.GET.get('code', None)
    if auth_code is None:
        return HttpResponseBadRequest()

    bearer = getBearerToken(auth_code)
    realmId = request.GET.get('realmId', None)
    updateSession(request, bearer.accessToken, bearer.refreshToken, realmId)

    # Validate JWT tokens only for OpenID scope
    if bearer.idToken is not None:
        if not validateJWTToken(bearer.idToken):
            return HttpResponse('JWT Validation failed. Please try signing in again.')
        else:
            return redirect('sampleAppOAuth2:connected')
    else:
        return redirect('sampleAppOAuth2:connected')


def connected(request):
    access_token = request.session.get('accessToken', None)
    if access_token is None:
        return HttpResponse('Your Bearer token has expired, please initiate Sign In With Intuit flow again')

    refresh_token = request.session.get('refreshToken', None)
    realmId = request.session['realmId']
    if realmId is None:
        user_profile_response, status_code = getUserProfile(access_token)

        if status_code >= 400:
            # if call to User Profile Service doesn't succeed then get a new bearer token from refresh token
            # and try again
            bearer = getBearerTokenFromRefreshToken(refresh_token)
            user_profile_response, status_code = getUserProfile(bearer.accessToken)
            updateSession(request, bearer.accessToken, bearer.refreshToken, request.session.get('realmId', None),
                          name=user_profile_response.get('givenName', None))

            if status_code >= 400:
                return HttpResponseServerError()
        c = {
            'first_name': user_profile_response.get('givenName', ' '),
        }
    else:
        if request.session.get('name') is None:
            name = ''
        else:
            name = request.session.get('name')
        c = {
            'first_name': name,
        }

    session = Session()
    c['customer_balances'] = session.query(CustomerBalance).all()
    session.close()
    return render(request, 'connected.html', context=c)


def disconnect(request):
    access_token = request.session.get('accessToken', None)
    refresh_token = request.session.get('refreshToken', None)

    revoke_response = ''
    if access_token is not None:
        revoke_response = revokeToken(access_token)
    elif refresh_token is not None:
        revoke_response = revokeToken(refresh_token)
    else:
        return HttpResponse('No accessToken or refreshToken found, Please connect again')

    request.session.flush()
    return HttpResponse(revoke_response)


def refreshTokenCall(request):
    refresh_token = request.session.get('refreshToken', None)
    if refresh_token is None:
        return HttpResponse('Not authorized')
    bearer = getBearerTokenFromRefreshToken(refresh_token)

    if isinstance(bearer, str):
        return HttpResponse(bearer)
    else:
        return HttpResponse('Access Token: ' + bearer.accessToken + ', Refresh Token: ' + bearer.refreshToken)


def apiCall(request):
    access_token = request.session.get('accessToken', None)
    if access_token is None:
        return HttpResponse('Your Bearer token has expired, please initiate C2QB flow again')

    realmId = request.session['realmId']
    if realmId is None:
        return HttpResponse('No realm ID. QBO calls only work if the accounting scope was passed!')

    refresh_token = request.session['refreshToken']
    customer_balance_response, status_code = getCustomerBalance(access_token, realmId)

    if status_code >= 400:
        # if call to QBO doesn't succeed then get a new bearer token from refresh token and try again
        bearer = getBearerTokenFromRefreshToken(refresh_token)
        updateSession(request, bearer.accessToken, bearer.refreshToken, realmId)
        customer_balance_response, status_code = getCustomerBalance(bearer.accessToken, realmId)
        if status_code >= 400:
            return HttpResponseServerError()

    columns = [column['ColTitle'] or column['ColType'] for column in customer_balance_response['Columns']['Column']]
    rows = transform_customer_balance_rows(customer_balance_response['Rows']['Row'])['rows']
    data_frame = pd.DataFrame.from_dict(rows, orient='index', columns=columns)

    data_frame.rename(columns={'Customer': 'customer', 'Total': 'balance'}, inplace=True)
    data_frame.to_sql('customer_balance', con=settings.DB_ENGINE, if_exists='append', index=False)

    time = parse(customer_balance_response['Header']['Time'])
    updated_log = UpdateLog(date=time.date())
    session = Session()
    session.add(updated_log)
    session.commit()
    report_name = customer_balance_response['Header']['ReportName']
    date_macro = customer_balance_response['Header']['DateMacro'] if 'DateMacro' in customer_balance_response[
        'Header'] else customer_balance_response['Header']['EndPeriod']

    # update_report = {'report_name': report_name, 'date_macro': date_macro, 'updated_at': time.strftime("%m/%d/%Y"),
    #                  'columns': ', '.join(columns), 'no_of_rows': len(rows),
    #                  'customer_balances': session.query(CustomerBalance).all()}
    session.close()
    return HttpResponse('Report Name: ' + report_name + ', From: ' + date_macro + ', Updated At: ' +
                        time.strftime("%m/%d/%Y") + ', Columns: ' + ', '.join(columns) + ', Number of rows fetched: ' + str(len(rows)))

    # return render(request, 'connected.html', context=update_report)


def transform_customer_balance_rows(rows_dict, start_index=0, header=None):
    transformed_rows = {}
    indx = start_index
    for row in rows_dict:
        try:
            column_data = row['ColData']
            indx = indx + 1
            transformed_rows[indx] = [ColData['value'] for ColData in column_data]
        except (KeyError, TypeError) as e:
            if 'Rows' in row:
                data = transform_customer_balance_rows(row['Rows']['Row'], indx, row['Header']['ColData'][0])
                indx = data['start_index'] + 1
                transformed_rows.update(data['rows'])

    return {'rows': transformed_rows, 'start_index': indx}


def get_CSRF_token(request):
    token = request.session.get('csrfToken', None)
    if token is None:
        token = getSecretKey()
        request.session['csrfToken'] = token
    return token


def updateSession(request, access_token, refresh_token, realmId, name=None):
    request.session['accessToken'] = access_token
    request.session['refreshToken'] = refresh_token
    request.session['realmId'] = realmId
    request.session['name'] = name
