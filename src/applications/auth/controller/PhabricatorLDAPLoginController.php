<?php

/*
 * Copyright 2012 Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

final class PhabricatorLDAPLoginController extends PhabricatorAuthController {
  private $provider;
  
  public function shouldRequireLogin() {
    return false;
  }

  public function willProcessRequest(array $data) {
    $this->provider = new PhabricatorLDAPProvider();
  }

  public function processRequest() {
    if (!$this->provider->isProviderEnabled()) {
      return new Aphront400Response();
    }
    
    $current_user = $this->getRequest()->getUser();
    if ($current_user->getPHID()) {
      throw new Exception('You are already logged in');
    }
    
    $request = $this->getRequest();

    if ($request->isFormPost()) {
      try {
        $this->provider->auth($request->getStr('username'),
          $request->getStr('password'));

      } catch (Exception $e) {
        // TODO create error view
        $errors[] = $e->getMessage();
      }

      if (empty($errors)) {
        $ldap_info = $this->retrieveLDAPInfo($this->provider);

        if ($ldap_info->getID()) {
          $unguarded = AphrontWriteGuard::beginScopedUnguardedWrites();

          $known_user = id(new PhabricatorUser())->load($ldap_info->getUserID());

          $session_key = $known_user->establishSession('web');
          
          $this->saveLDAPInfo($ldap_info);
          
          $request->setCookie('phusr', $known_user->getUsername());
          $request->setCookie('phsid', $session_key);

          $uri = new PhutilURI('/login/validate/');
          $uri->setQueryParams(
            array(
              'phusr' => $known_user->getUsername(),
            ));

          return id(new AphrontRedirectResponse())->setURI((string)$uri);
        }
        
        $controller = newv('PhabricatorLDAPRegistrationController', array($this->getRequest()));
        $controller->setLDAPProvider($this->provider);
        $controller->setLDAPInfo($ldap_info);
        
        return $this->delegateToController($controller);
      }
    }
    
    $ldap_username = $request->getCookie('phusr');
    $ldapForm = new AphrontFormView();
    $ldapForm
      ->setUser($request->getUser())
      ->setAction('/login/ldap/')
      ->appendChild(
        id(new AphrontFormTextControl())
        ->setLabel('LDAP username')
        ->setName('username')
        ->setValue($ldap_username))
      ->appendChild(
        id(new AphrontFormPasswordControl())
        ->setLabel('Password')
        ->setName('password'));

    // TODO: Implement captcha
    /* if ($require_captcha) { */
    /*     $ldapForm->appendChild( */
    /*         id(new AphrontFormRecaptchaControl()) */
    /*         ->setError($e_captcha)); */
    /* } */

    $ldapForm
      ->appendChild(
        id(new AphrontFormSubmitControl())
        ->setValue('Login'));

    $forms['LDAP login'] = $ldapForm;
    
    $panel = new AphrontPanelView();
    $panel->setWidth(AphrontPanelView::WIDTH_FORM);
    $panel->appendChild('<h1>LDAP login</h1>');
    $panel->appendChild($ldapForm);        

    if (isset($errors) && count($errors) > 0) {
      $error_view = new AphrontErrorView();
      $error_view->setTitle('Login Failed');
      $error_view->setErrors($errors);
    }

    return $this->buildStandardPageResponse(
      array(
        $error_view,
        $panel,
      ),
      array(
        'title' => 'Login',
      ));
  }

  private function retrieveLDAPInfo(PhabricatorLDAPProvider $provider) {
    $ldap_info = id(new PhabricatorUserLDAPInfo())->loadOneWhere(
      'ldapUsername = %s',
      $provider->retrieveUsername());

    if (!$ldap_info) {
      $ldap_info = new PhabricatorUserLDAPInfo();
      $ldap_info->setLDAPUsername($provider->retrieveUsername());
    }

    return $ldap_info;
  }

  private function saveLDAPInfo(PhabricatorUserLDAPInfo $info) {
    // UNGUARDED WRITES: Logging-in users don't have their CSRF set up yet.
    $unguarded = AphrontWriteGuard::beginScopedUnguardedWrites();
    $info->save();
  }
}
