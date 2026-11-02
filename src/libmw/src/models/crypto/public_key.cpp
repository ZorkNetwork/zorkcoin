#include <mw/models/crypto/public_key.h>
#include <mw/models/crypto/secret_key.h>
#include <mw/crypto/public_keys.h>

PublicKey PublicKey::From(const SecretKey& key)
{
    return PublicKeys::Calculate(key.GetBigInt());
}

PublicKey PublicKey::From(const Commitment& commitment)
{
    return PublicKeys::Convert(commitment);
}

PublicKey PublicKey::Random()
{
    return PublicKey::From(SecretKey::Random());
}

bool PublicKey::IsValid() const noexcept
{
    return PublicKeys::IsValid(*this);
}

PublicKey PublicKey::Mul(const SecretKey& mul) const
{
    return PublicKeys::MultiplyKey(*this, mul);
}

PublicKey PublicKey::Div(const SecretKey& div) const
{
    return PublicKeys::DivideKey(*this, div);
}

PublicKey PublicKey::Add(const SecretKey& add) const
{
    return PublicKeys::Add({ *this, PublicKey::From(add) });
}

PublicKey PublicKey::Add(const PublicKey& add) const
{
    return PublicKeys::Add({*this, add});
}

PublicKey PublicKey::Sub(const SecretKey& sub) const
{
    return PublicKeys::Add({*this}, {PublicKey::From(sub)});
}

PublicKey PublicKey::Sub(const PublicKey& sub) const
{
    return PublicKeys::Add({*this}, {sub});
}
