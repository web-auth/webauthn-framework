import { Controller } from '@hotwired/stimulus';
export default class extends Controller {
    static values: {
        requestResultUrl: StringConstructor;
        requestOptionsUrl: StringConstructor;
        requestSuccessRedirectUri: StringConstructor;
        creationResultUrl: StringConstructor;
        creationOptionsUrl: StringConstructor;
        creationSuccessRedirectUri: StringConstructor;
        usernameField: StringConstructor;
        displayNameField: StringConstructor;
        attestationField: StringConstructor;
        userVerificationField: StringConstructor;
        residentKeyField: StringConstructor;
        requireResidentKeyField: StringConstructor;
        authenticatorAttachmentField: StringConstructor;
        useBrowserAutofill: BooleanConstructor;
    };
    initialize(): void;
    connect(): void;
    signin(event: Event): Promise<void>;
    signup(event: Event): Promise<void>;
    _dispatchEvent(name: string, payload: any): void;
    fetch(method: string, url: string, body: string): Promise<XMLHttpRequest>;
    _getData(): any;
}
